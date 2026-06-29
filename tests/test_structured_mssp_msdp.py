# SPDX-License-Identifier: Elastic-2.0
"""MSSP (opt 70) + MSDP (opt 69) -> structured-event forwarding (#146)."""
import unittest

from glyph_relay.structured import (
    MSSP, MSDP, parse_mssp, mssp_to_structured, parse_msdp,
    msdp_to_structured_events, structured_from_subneg,
    structured_events, structured_events_from_subneg,
    _MSSP_VAR, _MSSP_VAL, _MSDP_VAR, _MSDP_VAL,
    _MSDP_TABLE_OPEN, _MSDP_TABLE_CLOSE, _MAX_SUBNEG_BODY, _MSDP_MAX_DEPTH,
)


def _mssp(*pairs):
    """Build an MSSP subneg body: pairs of (name, [values])."""
    body = bytearray([MSSP])
    for name, values in pairs:
        body.append(_MSSP_VAR)
        body += name.encode()
        for v in values:
            body.append(_MSSP_VAL)
            body += v.encode()
    return bytes(body)


def _msdp_var(name, *value_tokens):
    out = bytearray([_MSDP_VAR])
    out += name.encode()
    out.append(_MSDP_VAL)
    for t in value_tokens:
        out += t if isinstance(t, (bytes, bytearray)) else t.encode()
    return bytes(out)


class MSSPTests(unittest.TestCase):
    def test_parse_single_and_multi_value(self):
        payload = _mssp(("NAME", ["Aardwolf"]), ("PORT", ["23", "4000"]))
        values = parse_mssp(payload)
        self.assertEqual(values["NAME"], ["Aardwolf"])
        self.assertEqual(values["PORT"], ["23", "4000"])

    def test_repeated_var_accumulates(self):
        payload = _mssp(("PORT", ["23"]), ("PORT", ["4000"]))
        self.assertEqual(parse_mssp(payload)["PORT"], ["23", "4000"])

    def test_non_mssp_payload_is_none(self):
        self.assertIsNone(parse_mssp(b"\xc9other"))  # opt 201, not 70

    def test_oversized_is_none(self):
        big = bytes([MSSP, _MSSP_VAR]) + b"N" + bytes([_MSSP_VAL]) + b"x" * (_MAX_SUBNEG_BODY + 10)
        self.assertIsNone(parse_mssp(big))

    def test_structured_event_shape(self):
        payload = _mssp(("NAME", ["Aardwolf"]), ("PLAYERS", ["42"]))
        ev = structured_from_subneg(payload)
        self.assertEqual(ev["type"], "serverStatus")
        self.assertEqual(ev["data"]["values"]["NAME"], ["Aardwolf"])
        self.assertEqual(ev["data"]["values"]["PLAYERS"], ["42"])

    def test_forwarded_via_structured_events(self):
        payload = _mssp(("NAME", ["Aardwolf"]))
        out = list(structured_events([("subneg", payload)]))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["type"], "serverStatus")


class MSDPTests(unittest.TestCase):
    def test_scalar_variables_parse(self):
        payload = bytes([MSDP]) + _msdp_var("HEALTH", "100")[1:]  # rebuild with opt byte
        # simpler: construct directly
        payload = bytearray([MSDP])
        payload += _msdp_var("HEALTH", "100")
        payload += _msdp_var("CHARACTER_NAME", "Aria")
        variables = parse_msdp(bytes(payload))
        self.assertEqual(variables["HEALTH"], "100")
        self.assertEqual(variables["CHARACTER_NAME"], "Aria")

    def test_vitals_aggregation(self):
        payload = bytearray([MSDP])
        payload += _msdp_var("HEALTH", "100")
        payload += _msdp_var("MANA", "30")
        payload += _msdp_var("CHARACTER_NAME", "Aria")
        payload += _msdp_var("LEVEL", "5")
        events = msdp_to_structured_events(parse_msdp(bytes(payload)))
        vit = [e for e in events if e["type"] == "vitals"]
        self.assertEqual(len(vit), 1)
        data = vit[0]["data"]
        self.assertEqual(data["gauges"]["HEALTH"], 100.0)
        self.assertEqual(data["gauges"]["MANA"], 30.0)
        self.assertEqual(data["name"], "Aria")
        self.assertEqual(data["level"], 5)

    def test_room_table_maps_to_room_event(self):
        # ROOM table: VAR ROOM VAL TABLE_OPEN (VAR VNUM VAL 7)(VAR NAME VAL Square) TABLE_CLOSE
        inner = bytearray()
        inner += _msdp_var("VNUM", "7")
        inner += _msdp_var("NAME", "Town Square")
        payload = bytearray([MSDP, _MSDP_VAR])
        payload += b"ROOM"
        payload.append(_MSDP_VAL)
        payload.append(_MSDP_TABLE_OPEN)
        payload += inner
        payload.append(_MSDP_TABLE_CLOSE)
        events = msdp_to_structured_events(parse_msdp(bytes(payload)))
        room = [e for e in events if e["type"] == "room"]
        self.assertEqual(len(room), 1)
        self.assertEqual(room[0]["data"]["id"], "7")
        self.assertEqual(room[0]["data"]["name"], "Town Square")

    def test_unknown_variable_preserved_as_raw(self):
        payload = bytearray([MSDP])
        payload += _msdp_var("SERVER_ID", "xyz")
        events = msdp_to_structured_events(parse_msdp(bytes(payload)))
        raw = [e for e in events if e["type"] == "raw"]
        self.assertEqual(len(raw), 1)
        self.assertEqual(raw[0]["data"]["package"], "SERVER_ID")
        self.assertEqual(raw[0]["data"]["json"], "xyz")

    def test_oversized_body_is_none(self):
        payload = bytes([MSDP, _MSDP_VAR]) + b"X" * (_MAX_SUBNEG_BODY + 5)
        self.assertIsNone(parse_msdp(payload))

    def test_depth_bomb_is_dropped(self):
        # A frame nested past the depth cap returns None (whole frame dropped).
        payload = bytearray([MSDP, _MSDP_VAR])
        payload += b"DEEP"
        payload.append(_MSDP_VAL)
        for _ in range(_MSDP_MAX_DEPTH + 5):
            payload.append(_MSDP_TABLE_OPEN)
            payload.append(_MSDP_VAR)
            payload += b"K"
            payload.append(_MSDP_VAL)
        self.assertIsNone(parse_msdp(bytes(payload)))

    def test_forwarded_via_structured_events_yields_multiple(self):
        payload = bytearray([MSDP])
        payload += _msdp_var("HEALTH", "100")
        payload += _msdp_var("SERVER_ID", "xyz")
        out = list(structured_events([("subneg", bytes(payload))]))
        types = sorted(e["type"] for e in out)
        self.assertEqual(types, ["raw", "vitals"])

    def test_from_subneg_returns_list_for_msdp(self):
        payload = bytearray([MSDP])
        payload += _msdp_var("HEALTH", "100")
        out = structured_events_from_subneg(bytes(payload))
        self.assertEqual(out[0]["type"], "vitals")


if __name__ == "__main__":
    unittest.main()
