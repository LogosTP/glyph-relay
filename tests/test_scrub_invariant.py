# SPDX-License-Identifier: Elastic-2.0
"""§3.1 load-bearing scrub invariant: the durable sink sits at/after Hub.publish,
which only ever sees post-_scrub payloads, so a raw MUD password is NEVER persisted.
Driven end-to-end against the stub MUD (the strongest possible guard)."""
import asyncio
import unittest

from glyph_relay.history import HistoryStore
from glyph_relay.sessions import SessionManager
from stub.stub_server import Room, handle


async def _wait(predicate, timeout=5.0):
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.05)
    return False


class ScrubInvariantTest(unittest.IsolatedAsyncioTestCase):
    async def _stub(self):
        room = Room()
        server = await asyncio.start_server(
            lambda r, w: handle(r, w, room), "127.0.0.1", 0)
        return server, server.sockets[0].getsockname()[1]

    async def test_durable_history_never_holds_the_raw_password(self):
        server, port = await self._stub()
        history = HistoryStore(":memory:")
        mgr = SessionManager(host="127.0.0.1", port=port, use_tls=False,
                             history=history, max_sessions_per_tenant=5)
        try:
            secret = "throwaway-pw-9173"
            token = await mgr.create_user_session(
                "a@x.com", secret, "Alice", tenant_id="A")
            # Log in (password is sent during the flow) and produce some output.
            self.assertTrue(await _wait(lambda: mgr._sessions[token].submit("say hi") == "ok"))
            self.assertTrue(await _wait(lambda: len(history.backlog("A", token)) > 0))
            joined = "".join(str(data) for _id, _kind, data
                             in history.backlog("A", token))
            # The password flowed over the wire (login) but must be masked everywhere
            # the durable sink can see — proving the sink is downstream of _scrub.
            self.assertNotIn(secret, joined)
            self.assertIn("********", joined)
        finally:
            await mgr.close_all()
            history.close()
            server.close()
            await server.wait_closed()


if __name__ == "__main__":
    unittest.main()
