# SPDX-License-Identifier: Elastic-2.0
import unittest

from glyph_relay.negotiator import (
    Negotiator, IAC, WILL, WONT, DO, DONT, SB, SE,
    BINARY, SGA, TTYPE, EOR, NAWS, CHARSET, GMCP, MSSP, MSDP,
    TTYPE_IS, TTYPE_SEND, CHARSET_REQUEST, CHARSET_ACCEPTED, CHARSET_REJECTED,
)


class NegotiationTest(unittest.TestCase):
    def setUp(self):
        self.n = Negotiator(cols=80, rows=24)

    def test_do_naws_is_accepted_with_will_and_initial_frame(self):
        r = self.n.receive_negotiation(DO, NAWS)
        self.assertEqual(
            r,
            bytes([IAC, WILL, NAWS, IAC, SB, NAWS, 0, 80, 0, 24, IAC, SE]),
        )
        self.assertTrue(self.n.local_enabled(NAWS))

    def test_do_ttype_is_accepted_with_will(self):
        r = self.n.receive_negotiation(DO, TTYPE)
        self.assertEqual(r, bytes([IAC, WILL, TTYPE]))
        self.assertTrue(self.n.local_enabled(TTYPE))

    def test_will_eor_is_accepted_with_do(self):
        r = self.n.receive_negotiation(WILL, EOR)
        self.assertEqual(r, bytes([IAC, DO, EOR]))
        self.assertTrue(self.n.remote_enabled(EOR))

    def test_will_charset_is_accepted_with_do(self):
        r = self.n.receive_negotiation(WILL, CHARSET)
        self.assertEqual(r, bytes([IAC, DO, CHARSET]))
        self.assertTrue(self.n.remote_enabled(CHARSET))

    def test_will_mssp_is_accepted_with_do(self):
        # #146: accepting MSSP lets the server stream its status metadata, which the
        # relay forwards as a serverStatus structured event.
        r = self.n.receive_negotiation(WILL, MSSP)
        self.assertEqual(r, bytes([IAC, DO, MSSP]))
        self.assertTrue(self.n.remote_enabled(MSSP))

    def test_will_msdp_is_accepted_with_do(self):
        r = self.n.receive_negotiation(WILL, MSDP)
        self.assertEqual(r, bytes([IAC, DO, MSDP]))
        self.assertTrue(self.n.remote_enabled(MSDP))

    def test_binary_is_accepted_both_directions(self):
        self.assertEqual(self.n.receive_negotiation(DO, BINARY), bytes([IAC, WILL, BINARY]))
        self.assertEqual(self.n.receive_negotiation(WILL, BINARY), bytes([IAC, DO, BINARY]))
        self.assertTrue(self.n.local_enabled(BINARY))
        self.assertTrue(self.n.remote_enabled(BINARY))

    def test_unsupported_option_is_refused(self):
        self.assertEqual(self.n.receive_negotiation(WILL, 86), bytes([IAC, DONT, 86]))  # COMPRESS2
        self.assertEqual(self.n.receive_negotiation(DO, 86), bytes([IAC, WONT, 86]))

    def test_sga_is_refused(self):
        self.assertEqual(self.n.receive_negotiation(DO, SGA), bytes([IAC, WONT, SGA]))
        self.assertEqual(self.n.receive_negotiation(WILL, SGA), bytes([IAC, DONT, SGA]))

    def test_repeated_do_naws_is_not_reacknowledged(self):
        self.n.receive_negotiation(DO, NAWS)
        self.assertEqual(self.n.receive_negotiation(DO, NAWS), b"")  # already YES -> silent

    def test_will_then_wont_disables_remote(self):
        self.n.receive_negotiation(WILL, EOR)
        self.assertEqual(self.n.receive_negotiation(WONT, EOR), bytes([IAC, DONT, EOR]))
        self.assertFalse(self.n.remote_enabled(EOR))

    def test_offer_remote_then_peer_will_needs_no_extra_reply(self):
        self.assertEqual(self.n.offer_remote(TTYPE), bytes([IAC, DO, TTYPE]))
        self.assertEqual(self.n.receive_negotiation(WILL, TTYPE), b"")
        self.assertTrue(self.n.remote_enabled(TTYPE))

    def test_offer_local_then_peer_do_needs_no_extra_reply(self):
        self.assertEqual(self.n.offer_local(EOR), bytes([IAC, WILL, EOR]))
        self.assertEqual(self.n.receive_negotiation(DO, EOR), b"")
        self.assertTrue(self.n.local_enabled(EOR))

    def test_will_gmcp_is_accepted_with_do_and_hello(self):
        # The relay negotiates GMCP for every client so the MUD's out-of-band data
        # reaches phones (#59). Accepting WILL GMCP replies DO and kicks off the
        # handshake (Core.Hello + Core.Supports.Set) so the MUD streams packages.
        reply = self.n.receive_negotiation(WILL, GMCP)
        self.assertTrue(reply.startswith(bytes([IAC, DO, GMCP])))
        self.assertTrue(self.n.remote_enabled(GMCP))
        self.assertIn(bytes([IAC, SB, GMCP]) + b"Core.Hello ", reply)
        self.assertIn(b'"client":"Glyph"', reply)
        self.assertIn(b"Core.Supports.Set ", reply)
        self.assertTrue(reply.endswith(bytes([IAC, SE])))

    def test_gmcp_hello_sent_only_once(self):
        first = self.n.receive_negotiation(WILL, GMCP)
        self.assertIn(b"Core.Hello ", first)
        # A re-offer while already enabled is silent (no duplicate handshake).
        self.assertEqual(self.n.receive_negotiation(WILL, GMCP), b"")


class SubnegotiationTest(unittest.TestCase):
    def test_ttype_send_walks_cycle_then_repeats_last(self):
        n = Negotiator(term_types=["XTERM-256COLOR", "XTERM", "MTTS 13"])
        send = bytes([TTYPE, TTYPE_SEND])

        def is_name(name):
            return (bytes([IAC, SB, TTYPE, TTYPE_IS])
                    + name.encode() + bytes([IAC, SE]))

        self.assertEqual(n.receive_subneg(send), is_name("XTERM-256COLOR"))
        self.assertEqual(n.receive_subneg(send), is_name("XTERM"))
        self.assertEqual(n.receive_subneg(send), is_name("MTTS 13"))
        self.assertEqual(n.receive_subneg(send), is_name("MTTS 13"))  # repeats last

    def test_charset_request_accepts_utf8(self):
        n = Negotiator()
        payload = bytes([CHARSET, CHARSET_REQUEST]) + b";UTF-8"
        self.assertEqual(
            n.receive_subneg(payload),
            bytes([IAC, SB, CHARSET, CHARSET_ACCEPTED]) + b"UTF-8" + bytes([IAC, SE]),
        )

    def test_charset_request_rejects_when_no_utf8(self):
        n = Negotiator()
        payload = bytes([CHARSET, CHARSET_REQUEST]) + b";LATIN-1"
        self.assertEqual(
            n.receive_subneg(payload),
            bytes([IAC, SB, CHARSET, CHARSET_REJECTED, IAC, SE]),
        )

    def test_charset_request_skips_ttable_prefix(self):
        n = Negotiator()
        payload = (bytes([CHARSET, CHARSET_REQUEST]) + b"[TTABLE]" + bytes([1])
                   + b";UTF-8")
        self.assertEqual(
            n.receive_subneg(payload),
            bytes([IAC, SB, CHARSET, CHARSET_ACCEPTED]) + b"UTF-8" + bytes([IAC, SE]),
        )

    def test_naws_frame_escapes_ff_byte(self):
        n = Negotiator(cols=255, rows=24)
        self.assertEqual(
            n.naws_sb(),
            bytes([IAC, SB, NAWS, 0, 255, 255, 0, 24, IAC, SE]),
        )

    def test_window_size_is_clamped(self):
        n = Negotiator()
        n.set_window_size(0, 100000)
        self.assertEqual((n.cols, n.rows), (1, 65535))


if __name__ == "__main__":
    unittest.main()
