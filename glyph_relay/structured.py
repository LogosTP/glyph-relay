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
    """Map one Telnet subneg ``payload`` to a StructuredEvent wire dict, or ``None``
    if it is not a GMCP package this build forwards. Pure; the caller publishes the
    dict to the hub under the ``"structured"`` SSE event name."""
    parsed = parse_gmcp(payload)
    if parsed is None:
        return None
    package, data = parsed
    return gmcp_to_structured(package, data)


def structured_events(events):
    """Yield StructuredEvent wire dicts for the GMCP subnegotiations in a codec
    event list, skipping prompts and non-GMCP subnegs. The relay readers publish
    each yielded dict to the hub as a ``"structured"`` SSE event."""
    for kind, payload in events:
        if kind != "subneg":
            continue
        structured = structured_from_subneg(payload)
        if structured is not None:
            yield structured


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
