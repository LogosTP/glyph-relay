# SPDX-License-Identifier: Elastic-2.0
"""Pure GMCP -> shared StructuredEvent wire mapping for the relay gateway (#59).

In relay mode the gateway speaks Telnet to the MUD; out-of-band protocols are
invisible to attached phones unless the gateway parses them and forwards them.
``TelnetCodec`` already surfaces each GMCP subnegotiation (Telnet option 201) as a
``("subneg", payload)`` event; this module turns those payloads into the
transport-agnostic ``StructuredEvent`` wire dict the iOS app decodes
(``ios/Sources/GlyphCore/StructuredEvent.swift``).

Stdlib only and pure (no I/O): bytes in, dict out. The wire envelope is

    {"type": <tag>, "data": <payload>}

matching the explicit ``CodingKeys`` on the Swift ``StructuredEvent`` so this
stdlib ``json`` output and the Swift ``JSONDecoder`` agree byte-for-byte.
``tests/fixtures/structured_wire.json`` is the shared golden file both suites check.
"""
import json

# Telnet option for the Generic MUD Communication Protocol (out-of-band JSON).
GMCP = 201
# MSSP (MUD Server Status Protocol, opt 70) and MSDP (MUD Server Data Protocol,
# opt 69). The relay forwards these as structured events too (#146) so a relay-mode
# client can resolve ServerFeaturePolicy exactly like direct mode.
MSSP = 70
MSDP = 69

# MSSP framing bytes inside the subneg body (de-facto protocol; mudhalla.net).
_MSSP_VAR = 1
_MSSP_VAL = 2

# MSDP framing bytes (tintin.mudhalla.net/protocols/msdp).
_MSDP_VAR = 1
_MSDP_VAL = 2
_MSDP_TABLE_OPEN = 3
_MSDP_TABLE_CLOSE = 4
_MSDP_ARRAY_OPEN = 5
_MSDP_ARRAY_CLOSE = 6

# Defensive caps mirroring the iOS MSSP/MSDP codecs: bound a hostile/runaway subneg
# so the relay isn't a soft target. 256 KiB body comfortably exceeds any real frame;
# MSDP depth 32 bounds native recursion against a depth-bomb that fits under the size cap.
_MAX_SUBNEG_BODY = 256 * 1024
_MSDP_MAX_DEPTH = 32

# MSDP standard reportable variables that drive the vitals HUD (mirrors MSDP.swift's
# vitalsVariables); anything else MSDP carries reaches the inspector as ``raw``.
_MSDP_VITALS = frozenset({
    "HEALTH", "HEALTH_MAX", "MAXHEALTH",
    "MANA", "MANA_MAX", "MAXMANA",
    "MOVEMENT", "MOVEMENT_MAX", "MAXMOVEMENT",
    "EXPERIENCE", "EXPERIENCE_MAX", "EXPERIENCE_TNL",
    "MONEY", "ALIGNMENT", "WIMPY",
    "OPPONENT_HEALTH", "OPPONENT_HEALTH_MAX", "OPPONENT_LEVEL", "OPPONENT_NAME",
    "CHARACTER_NAME", "LEVEL",
})

# GMCP packages whose JSON we map onto a typed StructuredEvent. Lower-cased for a
# case-insensitive match; anything not listed is preserved verbatim as ``raw``.
_VITALS_PACKAGES = ("char.vitals", "char.status", "char.stats")
_ROOM_PACKAGES = ("room.info",)


def parse_gmcp(payload):
    """Split a GMCP subneg ``payload`` (the bytes ``TelnetCodec`` surfaces, i.e.
    starting with the option byte 201) into ``(package, data)``.

    ``data`` is the decoded JSON body (any JSON type) or ``None`` when the package
    carries no body / an unparseable one. Returns ``None`` when ``payload`` is not
    GMCP or its package name is empty."""
    if not payload or payload[0] != GMCP:
        return None
    body = payload[1:].decode("utf-8", "replace")
    name, _sep, rest = body.partition(" ")
    name = name.strip()
    if not name:
        return None
    rest = rest.strip()
    if not rest:
        return name, None
    try:
        return name, json.loads(rest)
    except ValueError:
        return name, None


def gmcp_to_structured(package, data):
    """Map a parsed GMCP ``(package, data)`` onto a StructuredEvent wire dict.

    Known packages become their typed shape (vitals/room/commChannel); anything
    else is preserved verbatim as ``raw`` so the iOS inspector loses nothing (#65)."""
    low = package.lower()
    if low in _VITALS_PACKAGES:
        return _vitals_event(data)
    if low in _ROOM_PACKAGES:
        return _room_event(data)
    if low.startswith("comm.channel") and isinstance(data, dict):
        return _comm_event(data)
    if low.startswith("client.media."):
        media = _media_event(package, data)
        if media is not None:
            return media
    return _raw_event(package, data)


def structured_from_subneg(payload):
    """Map one Telnet subneg ``payload`` to a single StructuredEvent wire dict, or
    ``None`` when it is not a GMCP/MSSP frame this build forwards. (MSDP can yield
    SEVERAL events from one frame — use ``structured_events_from_subneg`` for the full
    list.) Pure; the caller publishes the dict under the ``"structured"`` SSE name."""
    parsed = parse_gmcp(payload)
    if parsed is not None:
        package, data = parsed
        return gmcp_to_structured(package, data)
    if payload and payload[0] == MSSP:
        status = parse_mssp(payload)
        if status is not None:
            return mssp_to_structured(status)
    return None


def structured_events_from_subneg(payload):
    """Zero or more StructuredEvent wire dicts for one subneg: GMCP/MSSP yield at most
    one; MSDP may batch several variables (vitals + room + raws) into one frame (#146)."""
    if not payload:
        return []
    option = payload[0]
    if option == GMCP:
        ev = structured_from_subneg(payload)
        return [ev] if ev is not None else []
    if option == MSSP:
        status = parse_mssp(payload)
        return [mssp_to_structured(status)] if status is not None else []
    if option == MSDP:
        variables = parse_msdp(payload)
        if variables is None:
            return []
        return msdp_to_structured_events(variables)
    return []


def structured_events(events):
    """Yield StructuredEvent wire dicts for the GMCP/MSSP/MSDP subnegotiations in a
    codec event list, skipping prompts and unforwarded subnegs. The relay readers
    publish each yielded dict to the hub as a ``"structured"`` SSE event (#59/#146)."""
    for kind, payload in events:
        if kind != "subneg":
            continue
        for structured in structured_events_from_subneg(payload):
            yield structured


# --- MSSP (opt 70) -> serverStatus ------------------------------------------

def parse_mssp(payload):
    """Parse an MSSP subneg ``payload`` (starting with option byte 70) into
    ``{name: [values]}``. Both multi-value forms (several MSSP_VAL under one
    MSSP_VAR, or a repeated MSSP_VAR) accumulate. Empty names are skipped. Returns
    ``None`` when ``payload`` is not MSSP or its body exceeds the size cap."""
    if not payload or payload[0] != MSSP:
        return None
    body = payload[1:]
    if len(body) > _MAX_SUBNEG_BODY:
        return None
    # Tokenize into (field, bytes); field is "name" (after VAR) or "value" (after VAL).
    tokens = []
    field = None
    buf = bytearray()
    for b in body:
        if b == _MSSP_VAR or b == _MSSP_VAL:
            if field is not None:
                tokens.append((field, bytes(buf)))
            field = "name" if b == _MSSP_VAR else "value"
            buf = bytearray()
        else:
            buf.append(b)
    if field is not None:
        tokens.append((field, bytes(buf)))
    values = {}
    current_key = None
    for ftype, raw in tokens:
        text = raw.decode("utf-8", "replace")
        if ftype == "name":
            if not text:
                current_key = None
                continue
            current_key = text
            values.setdefault(text, [])
        elif current_key is not None:
            values.setdefault(current_key, []).append(text)
    return values


def mssp_to_structured(values):
    """An MSSP ``{name: [values]}`` map -> the ``serverStatus`` wire shape. Matches the
    Swift ``ServerStatus`` Codable (single ``values`` field) so direct + relay agree."""
    return {"type": "serverStatus", "data": {"values": values}}


# --- MSDP (opt 69) -> vitals / room / raw -----------------------------------

class _MsdpParser:
    """Recursive-descent parser over an MSDP body (mirrors MSDP.swift). Scalars become
    ``str``, tables become ``dict``, arrays become ``list``; descent is bounded at
    ``_MSDP_MAX_DEPTH`` (a depth-bomb sets ``overflowed`` and the frame is dropped)."""

    def __init__(self, body):
        self.b = body
        self.i = 0
        self.depth = 0
        self.overflowed = False

    def parse_pairs(self, terminator):
        obj = {}
        n = len(self.b)
        while self.i < n and self.b[self.i] != terminator:
            if self.b[self.i] != _MSDP_VAR:
                self.i += 1            # resync on stray bytes
                continue
            self.i += 1
            name = self.read_scalar()
            if self.i < n and self.b[self.i] == _MSDP_VAL:
                self.i += 1
                obj[name] = self.parse_value()
            else:
                obj[name] = ""          # VAR with no VAL — preserve the name
        if terminator is not None and self.i < n:
            self.i += 1                 # consume the CLOSE byte
        return obj

    def parse_value(self):
        if self.i >= len(self.b):
            return ""
        c = self.b[self.i]
        if c == _MSDP_TABLE_OPEN:
            self.i += 1
            if self.depth >= _MSDP_MAX_DEPTH:
                self.overflowed = True
                return {}
            self.depth += 1
            try:
                return self.parse_pairs(_MSDP_TABLE_CLOSE)
            finally:
                self.depth -= 1
        if c == _MSDP_ARRAY_OPEN:
            self.i += 1
            if self.depth >= _MSDP_MAX_DEPTH:
                self.overflowed = True
                return []
            self.depth += 1
            try:
                return self.parse_array()
            finally:
                self.depth -= 1
        return self.read_scalar()

    def parse_array(self):
        arr = []
        n = len(self.b)
        while self.i < n and self.b[self.i] != _MSDP_ARRAY_CLOSE:
            if self.b[self.i] != _MSDP_VAL:
                self.i += 1
                continue
            self.i += 1
            arr.append(self.parse_value())
        if self.i < n:
            self.i += 1                 # consume ARRAY_CLOSE
        return arr

    def read_scalar(self):
        start = self.i
        n = len(self.b)
        while self.i < n and self.b[self.i] > _MSDP_ARRAY_CLOSE:
            self.i += 1
        return bytes(self.b[start:self.i]).decode("utf-8", "replace")


def parse_msdp(payload):
    """Decode an MSDP subneg ``payload`` (starting with option byte 69) into its
    top-level ``{name: value}`` map (scalars/tables/arrays). Returns ``None`` when not
    MSDP, oversized, or nested past the depth cap."""
    if not payload or payload[0] != MSDP:
        return None
    body = payload[1:]
    if len(body) > _MAX_SUBNEG_BODY:
        return None
    parser = _MsdpParser(body)
    result = parser.parse_pairs(None)
    if parser.overflowed:
        return None
    return result


def msdp_to_structured_events(variables):
    """Map a parsed MSDP variable map onto StructuredEvent wire dicts (mirrors
    MSDP.swift): vitals are aggregated into one ``vitals`` event, ``ROOM`` becomes a
    ``room`` event, everything else is preserved verbatim as ``raw``. Deterministic
    order: vitals, then room, then unknowns sorted by name."""
    vitals_bag = {}
    room_event = None
    raw_events = []
    for name in sorted(variables.keys()):
        value = variables[name]
        upper = name.upper()
        if upper == "ROOM" and isinstance(value, dict):
            room_event = _room_event(value)
        elif upper in _MSDP_VITALS:
            vitals_bag[name] = value
        else:
            raw_events.append(_raw_event(name, value))
    events = []
    if vitals_bag:
        events.append(_msdp_vitals_event(vitals_bag))
    if room_event is not None:
        events.append(room_event)
    events.extend(raw_events)
    return events


def _msdp_vitals_event(variables):
    """Aggregate MSDP vitals variables into one ``vitals`` event. MSDP scalars are
    strings, so numeric fields are coerced (matching GMCP); CHARACTER_NAME -> name,
    LEVEL -> level; non-numeric vitals stay as verbatim string fields."""
    name = None
    level = None
    gauges = {}
    fields = {}
    for key, value in variables.items():
        upper = key.upper()
        if upper == "CHARACTER_NAME":
            name = _msdp_scalar_string(value)
            continue
        if upper == "LEVEL":
            num = _coerce_number(value)
            if num is not None:
                level = int(num)
                continue
        num = _coerce_number(value)
        if num is not None:
            gauges[key] = num
        else:
            fields[key] = _msdp_scalar_string(value)
    payload = {"gauges": gauges, "fields": fields}
    if name is not None:
        payload["name"] = name
    if level is not None:
        payload["level"] = level
    return {"type": "vitals", "data": payload}


def _msdp_scalar_string(value):
    """An MSDP value as a plain string (values are strings on the wire; a container
    falls back to compact JSON so nothing is silently lost)."""
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return "{}".format(value)
    if value is None:
        return ""
    return json.dumps(value, separators=(",", ":"))


# --- typed mappings ---------------------------------------------------------

def _coerce_number(value):
    """A GMCP scalar as a float (games often send numbers as JSON strings), or
    ``None`` when it is not numeric. ``bool`` is intentionally not a number."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _pick(lower_data, keys):
    """The first present, non-null value among ``keys`` in a lower-cased dict."""
    for key in keys:
        if lower_data.get(key) is not None:
            return lower_data[key]
    return None


def _vitals_event(data):
    """GMCP ``Char.Vitals`` / ``Char.Status`` -> the ``vitals`` shape. Numeric
    fields become gauges (floats), the rest stay as verbatim string fields; ``name``
    and ``level`` are surfaced because nearly every HUD shows them (#66)."""
    name = None
    level = None
    gauges = {}
    fields = {}
    if isinstance(data, dict):
        for key, value in data.items():
            low = key.lower()
            if low == "name":
                name = "{}".format(value)
                continue
            if low == "level":
                num = _coerce_number(value)
                if num is not None:
                    level = int(num)
                    continue
            num = _coerce_number(value)
            if num is not None:
                gauges[key] = num
            else:
                fields[key] = "{}".format(value)
    payload = {"gauges": gauges, "fields": fields}
    if name is not None:
        payload["name"] = name
    if level is not None:
        payload["level"] = level
    return {"type": "vitals", "data": payload}


def _room_event(data):
    """GMCP ``Room.Info`` -> the ``room`` shape: id/name/area, a direction->dest-id
    exit map, and optional integer coordinates for the mapper (#67)."""
    out = {"exits": {}}
    if isinstance(data, dict):
        low = {k.lower(): v for k, v in data.items()}
        rid = _pick(low, ("num", "id", "vnum", "roomvnum"))
        if rid is not None:
            out["id"] = "{}".format(rid)
        name = low.get("name")
        if isinstance(name, str):
            out["name"] = name
        area = _pick(low, ("area", "zone"))
        if isinstance(area, str):
            out["area"] = area
        exits = low.get("exits")
        if isinstance(exits, dict):
            out["exits"] = {d: "{}".format(dest) for d, dest in exits.items()}
        coords = _coordinates(low.get("coord") or low.get("coords"))
        if coords is not None:
            out["coordinates"] = coords
    return {"type": "room", "data": out}


def _coordinates(value):
    """A GMCP coord dict -> integer ``{x, y, z}`` (+ optional ``mapID``), or ``None``
    when no axis is present. Swift's ``Coordinates`` requires x/y/z, so all three are
    always emitted (defaulting to 0)."""
    if not isinstance(value, dict):
        return None
    low = {k.lower(): v for k, v in value.items()}
    x = _coerce_number(low.get("x"))
    y = _coerce_number(low.get("y"))
    z = _coerce_number(low.get("z"))
    if x is None and y is None and z is None:
        return None
    coord = {"x": int(x or 0), "y": int(y or 0), "z": int(z or 0)}
    map_id = _pick(low, ("map", "mapid", "id"))
    if map_id is not None:
        coord["mapID"] = "{}".format(map_id)
    return coord


def _comm_event(data):
    """GMCP ``Comm.Channel`` -> the ``commChannel`` shape (channel/sender/text). This
    is user-generated content; the iOS comms view moderates it on display (#68)."""
    low = {k.lower(): v for k, v in data.items()}
    out = {"channel": "", "text": ""}
    channel = _pick(low, ("chan", "channel", "name"))
    if channel is not None:
        out["channel"] = "{}".format(channel)
    text = _pick(low, ("text", "msg", "message"))
    if text is not None:
        out["text"] = "{}".format(text)
    sender = _pick(low, ("talker", "player", "sender", "from"))
    if sender is not None:
        out["sender"] = "{}".format(sender)
    return {"type": "commChannel", "data": out}


def _media_str(value):
    """A JSON string field, or ``None`` when it is not a string. Mirrors the Swift core's
    ``MSP.string`` helper so direct and relay agree on which fields survive."""
    return value if isinstance(value, str) else None


def _media_int(value):
    """A JSON number / numeric-string as an int, or ``None`` (Swift ``MSP.int``). ``bool``
    is intentionally not an int; a non-integral string (e.g. "1.5") yields ``None``."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


def _media_bool(value):
    """A JSON bool, or a number's truthiness, else ``None`` (Swift ``MSP.bool``)."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return None


def _media_event(package, data):
    """MCMP (media over GMCP) -> the inert ``media`` cue shape (#72), mirroring
    ``MSP.mediaCue`` in the Swift core. ``Client.Media.Play`` becomes a sound/music cue and
    ``Client.Media.Stop`` a stop cue; other ``Client.Media.*`` (``Load`` / ``Default``)
    carry no playback intent, so they return ``None`` and are preserved verbatim as ``raw``.

    The cue is INERT: the iOS media gate (default-OFF per server, HTTPS-only, host allowlist,
    download size cap) still decides before any fetch/playback — nothing is fetched here. The
    wire keys match the Swift ``MediaCue`` encoding (note the body field ``continue`` -> the
    encoded key ``continues``), and only present fields are emitted (Swift omits nil optionals)."""
    low = package.lower()
    body = {k.lower(): v for k, v in data.items()} if isinstance(data, dict) else {}
    if low == "client.media.stop":
        out = {"kind": "stop"}
        raw_tag = body["tag"] if "tag" in body else body.get("type")
        tag = _media_str(raw_tag)
        if tag is not None:
            out["type"] = tag
        return {"type": "media", "data": out}
    if low != "client.media.play":
        return None
    type_field = _media_str(body.get("type"))
    out = {"kind": "music" if (type_field or "").lower() == "music" else "sound"}
    name = _media_str(body.get("name"))
    if name is not None:
        out["file"] = name
    url = _media_str(body.get("url"))
    if url is not None:
        out["url"] = url
    volume = _media_int(body.get("volume"))
    if volume is not None:
        out["volume"] = volume
    loops = _media_int(body.get("loops"))
    if loops is not None:
        out["loops"] = loops
    priority = _media_int(body.get("priority"))
    if priority is not None:
        out["priority"] = priority
    tag = _media_str(body.get("tag"))
    if tag is not None:
        out["type"] = tag
    continues = _media_bool(body.get("continue"))
    if continues is not None:
        out["continues"] = continues
    return {"type": "media", "data": out}


def _raw_event(package, data):
    """Any unmodeled package, preserved verbatim under its dotted name so the iOS
    inspector can show it (#65). ``data`` is the decoded JSON body or ``None``."""
    return {"type": "raw", "data": {"package": package, "json": data}}
