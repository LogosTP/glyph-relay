# SPDX-License-Identifier: Elastic-2.0
import json
import os
import unittest

from glyph_relay.structured import (
    GMCP, parse_gmcp, gmcp_to_structured, structured_from_subneg, structured_events,
)

_FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "structured_wire.json")


def _gmcp(text):
    """A GMCP subneg payload as TelnetCodec surfaces it: option byte then body."""
    return bytes([GMCP]) + text.encode("utf-8")


class ParseGmcpTest(unittest.TestCase):
    def test_splits_package_and_json_body(self):
        self.assertEqual(
            parse_gmcp(_gmcp('Char.Vitals {"hp":"100"}')),
            ("Char.Vitals", {"hp": "100"}),
        )

    def test_package_without_body_yields_none_data(self):
        self.assertEqual(parse_gmcp(_gmcp("Core.Ping")), ("Core.Ping", None))

    def test_non_gmcp_option_returns_none(self):
        self.assertIsNone(parse_gmcp(bytes([31]) + b"\x00\x50\x00\x18"))  # NAWS, not GMCP
        self.assertIsNone(parse_gmcp(b""))

    def test_malformed_json_falls_back_to_none_data(self):
        self.assertEqual(parse_gmcp(_gmcp("Char.Vitals {bad")), ("Char.Vitals", None))


class VitalsMappingTest(unittest.TestCase):
    def test_numbers_become_float_gauges_and_name_level_surface(self):
        ev = structured_from_subneg(
            _gmcp('Char.Vitals {"name":"Aria","level":"42","hp":"100","class":"mage"}'))
        self.assertEqual(ev["type"], "vitals")
        self.assertEqual(ev["data"]["name"], "Aria")
        self.assertEqual(ev["data"]["level"], 42)
        self.assertEqual(ev["data"]["gauges"], {"hp": 100.0})
        self.assertEqual(ev["data"]["fields"], {"class": "mage"})
        # gauges are JSON numbers (Swift decodes [String: Double]); level is an int.
        self.assertIsInstance(ev["data"]["gauges"]["hp"], float)
        self.assertIsInstance(ev["data"]["level"], int)

    def test_required_keys_always_present_for_swift_decode(self):
        # Swift's Vitals has non-optional gauges/fields, so both keys must always be
        # emitted even when empty, or JSONDecoder throws keyNotFound.
        ev = structured_from_subneg(_gmcp("Char.Vitals"))
        self.assertIn("gauges", ev["data"])
        self.assertIn("fields", ev["data"])

    def test_bool_is_not_a_gauge(self):
        ev = structured_from_subneg(_gmcp('Char.Status {"pk":true}'))
        self.assertEqual(ev["data"]["gauges"], {})
        self.assertEqual(ev["data"]["fields"], {"pk": "True"})


class RoomMappingTest(unittest.TestCase):
    def test_room_info_maps_id_name_area_and_exits(self):
        ev = structured_from_subneg(_gmcp(
            'Room.Info {"num":12345,"name":"A dark cave","area":"Caverns",'
            '"exits":{"n":12346,"e":12350}}'))
        self.assertEqual(ev["type"], "room")
        self.assertEqual(ev["data"]["id"], "12345")
        self.assertEqual(ev["data"]["name"], "A dark cave")
        self.assertEqual(ev["data"]["area"], "Caverns")
        self.assertEqual(ev["data"]["exits"], {"n": "12346", "e": "12350"})

    def test_coordinates_are_integers_when_present(self):
        ev = structured_from_subneg(_gmcp(
            'Room.Info {"num":1,"coord":{"id":"main","x":3,"y":-4,"z":0}}'))
        self.assertEqual(ev["data"]["coordinates"],
                         {"x": 3, "y": -4, "z": 0, "mapID": "main"})

    def test_exits_always_present(self):
        ev = structured_from_subneg(_gmcp('Room.Info {"num":7}'))
        self.assertEqual(ev["data"]["exits"], {})


class CommMappingTest(unittest.TestCase):
    def test_comm_channel_maps_channel_sender_text(self):
        ev = structured_from_subneg(_gmcp(
            'Comm.Channel.Text {"channel":"gossip","talker":"Bob","text":"hi all"}'))
        self.assertEqual(ev["type"], "commChannel")
        self.assertEqual(ev["data"]["channel"], "gossip")
        self.assertEqual(ev["data"]["sender"], "Bob")
        self.assertEqual(ev["data"]["text"], "hi all")


class MediaMappingTest(unittest.TestCase):
    """#72: MCMP (media over GMCP) — Client.Media.* maps to the inert ``media`` cue, so
    the relay path delivers media cues to the app IDENTICALLY to the direct GMCP codec
    (ios/Sources/GlyphCore/GMCP.swift). The app then gates them (default-OFF, per server)."""

    def test_play_maps_to_media_cue(self):
        ev = structured_from_subneg(_gmcp(
            'Client.Media.Play {"type":"music","name":"theme.mp3",'
            '"url":"https://m.example.org/","volume":60,"loops":-1,"tag":"bg"}'))
        self.assertEqual(ev, {"type": "media", "data": {
            "kind": "music", "file": "theme.mp3", "url": "https://m.example.org/",
            "volume": 60, "loops": -1, "type": "bg"}})

    def test_play_without_type_defaults_to_sound_and_omits_absent_fields(self):
        ev = structured_from_subneg(_gmcp(
            'Client.Media.Play {"name":"click.wav","url":"https://m.example.org/"}'))
        self.assertEqual(ev, {"type": "media", "data": {
            "kind": "sound", "file": "click.wav", "url": "https://m.example.org/"}})

    def test_continue_field_maps_to_continues_wire_key(self):
        # The MCMP body field is "continue"; the Swift MediaCue encodes it as "continues".
        ev = structured_from_subneg(_gmcp(
            'Client.Media.Play {"name":"a.wav","url":"https://m.example.org/","continue":true}'))
        self.assertEqual(ev["data"]["continues"], True)
        self.assertNotIn("continue", ev["data"])

    def test_stop_maps_to_stop_cue(self):
        ev = structured_from_subneg(_gmcp('Client.Media.Stop {"tag":"bg"}'))
        self.assertEqual(ev, {"type": "media", "data": {"kind": "stop", "type": "bg"}})

    def test_load_without_playback_intent_is_preserved_as_raw(self):
        ev = structured_from_subneg(_gmcp('Client.Media.Load {"name":"a.wav"}'))
        self.assertEqual(ev, {"type": "raw",
                              "data": {"package": "Client.Media.Load",
                                       "json": {"name": "a.wav"}}})


class RawMappingTest(unittest.TestCase):
    def test_unknown_package_preserved_verbatim(self):
        ev = gmcp_to_structured("Foo.Bar", {"x": 1})
        self.assertEqual(ev, {"type": "raw",
                              "data": {"package": "Foo.Bar", "json": {"x": 1}}})

    def test_bodyless_unknown_package_has_null_json(self):
        ev = structured_from_subneg(_gmcp("Some.Thing"))
        self.assertEqual(ev, {"type": "raw",
                              "data": {"package": "Some.Thing", "json": None}})


class StructuredEventsGlueTest(unittest.TestCase):
    def test_only_gmcp_subnegs_yield_events(self):
        events = [
            ("prompt", "GA"),
            ("subneg", bytes([31]) + b"\x00\x50\x00\x18"),       # NAWS — ignored
            ("subneg", _gmcp('Char.Vitals {"hp":"5"}')),         # GMCP — mapped
        ]
        out = list(structured_events(events))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["type"], "vitals")


class SharedWireFixtureTest(unittest.TestCase):
    """The gateway must EMIT exactly the bytes the Swift suite DECODES. This asserts
    the Python side of the shared golden fixture (the Swift side is
    StructuredWireFixtureTests.swift); together they pin one cross-language shape."""

    def test_gateway_emits_the_golden_fixture(self):
        with open(_FIXTURE, encoding="utf-8") as handle:
            fixture = json.load(handle)

        payloads = [
            _gmcp('Char.Vitals {"name":"Aria","level":"42","hp":"100","maxhp":"120",'
                  '"mp":"30","class":"mage"}'),
            _gmcp('Room.Info {"num":12345,"name":"A dark cave","area":"Caverns",'
                  '"exits":{"n":12346,"e":12350}}'),
            _gmcp('Comm.Channel.Text {"channel":"gossip","talker":"Bob","text":"hi all"}'),
            _gmcp('Foo.Bar {"x":1}'),
            _gmcp('Client.Media.Play {"type":"music","name":"theme.mp3",'
                  '"url":"https://media.example.org/","volume":60,"loops":-1,"tag":"bg"}'),
        ]
        self.assertEqual(len(payloads), len(fixture))
        for payload, expected in zip(payloads, fixture):
            self.assertEqual(structured_from_subneg(payload), expected)


if __name__ == "__main__":
    unittest.main()
