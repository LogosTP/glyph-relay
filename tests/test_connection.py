# SPDX-License-Identifier: Elastic-2.0
import asyncio
import ssl
import unittest

from glyph_relay.connection import Connection, make_ssl_context
from glyph_relay.negotiator import Negotiator, NAWS, DO, IAC, SB, SE
from stub.stub_server import Room, handle
from tests._certs import ensure_dev_cert


class SslContextTest(unittest.TestCase):
    def test_verify_off_disables_checks(self):
        ctx = make_ssl_context(verify=False)
        self.assertFalse(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)


class ConnectionTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.room = Room()
        self.server = await asyncio.start_server(
            lambda r, w: handle(r, w, self.room), "127.0.0.1", 0
        )
        self.port = self.server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        self.server.close()
        await self.server.wait_closed()

    async def test_connect_login_and_chat_roundtrip(self):
        conn = Connection("127.0.0.1", self.port, use_tls=False)
        await conn.connect()
        seen = []

        async def pump():
            async for text, _events in conn.receive():
                seen.append(text)

        task = asyncio.create_task(pump())
        await asyncio.sleep(0.1)
        await conn.send("tester@example.com")   # answer the email prompt
        await asyncio.sleep(0.1)
        await conn.send("throwaway-pw")          # answer the password prompt
        await asyncio.sleep(0.1)
        await conn.send("throwaway-pw")          # re-enter to confirm the password
        await asyncio.sleep(0.1)
        await conn.send("Tester")                # answer the character-name prompt
        await asyncio.sleep(0.1)
        await conn.send("yes")                   # confirm character creation
        await asyncio.sleep(0.1)
        await conn.send("say hello there")       # chat -> broadcast back to us
        await asyncio.sleep(0.2)

        joined = "".join(seen)
        self.assertIn("email", joined.lower())
        self.assertIn("Tester: hello there", joined)

        task.cancel()
        await conn.close()

    async def test_raw_logger_receives_sent_and_recv_bytes(self):
        events = []
        conn = Connection(
            "127.0.0.1", self.port, use_tls=False,
            raw_logger=lambda direction, data: events.append((direction, data)),
        )
        await conn.connect()

        async def pump():
            async for _text, _events in conn.receive():
                pass

        task = asyncio.create_task(pump())
        await asyncio.sleep(0.1)
        await conn.send("tester@example.com")
        await asyncio.sleep(0.1)
        directions = [d for d, _ in events]
        self.assertIn("RECV", directions)
        self.assertIn("SENT", directions)
        task.cancel()
        await conn.close()


class ConnectionTlsTest(unittest.IsolatedAsyncioTestCase):
    async def test_implicit_tls_roundtrip_through_connection(self):
        certs = ensure_dev_cert()
        if certs is None:
            self.skipTest("openssl not available")
        cert, key = certs
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(cert, key)
        room = Room()
        server = await asyncio.start_server(
            lambda r, w: handle(r, w, room), "127.0.0.1", 0, ssl=sctx
        )
        port = server.sockets[0].getsockname()[1]

        conn = Connection("127.0.0.1", port, use_tls=True, verify=False)
        await conn.connect()
        seen = []

        async def pump():
            async for text, _events in conn.receive():
                seen.append(text)

        task = asyncio.create_task(pump())
        await asyncio.sleep(0.2)
        self.assertIn("email", "".join(seen).lower())

        task.cancel()
        await conn.close()
        server.close()
        await server.wait_closed()


class _FakeWriter:
    def __init__(self):
        self.buf = bytearray()

    def write(self, data):
        self.buf += data

    async def drain(self):
        pass

    def close(self):
        pass


class UpdateWindowSizeTest(unittest.IsolatedAsyncioTestCase):
    async def test_sends_naws_frame_when_naws_enabled(self):
        neg = Negotiator(cols=80, rows=24)
        neg.receive_negotiation(DO, NAWS)        # server enabled NAWS -> local on
        conn = Connection("h", 0, use_tls=False, negotiator=neg)
        conn._writer = _FakeWriter()
        await conn.update_window_size(100, 40)
        self.assertIn(
            bytes([IAC, SB, NAWS, 0, 100, 0, 40, IAC, SE]),
            bytes(conn._writer.buf),
        )

    async def test_noop_when_naws_not_enabled(self):
        neg = Negotiator(cols=80, rows=24)         # never agreed to NAWS
        conn = Connection("h", 0, use_tls=False, negotiator=neg)
        conn._writer = _FakeWriter()
        await conn.update_window_size(100, 40)
        self.assertEqual(bytes(conn._writer.buf), b"")


if __name__ == "__main__":
    unittest.main()
