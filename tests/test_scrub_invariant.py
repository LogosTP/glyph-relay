# SPDX-License-Identifier: Elastic-2.0
"""§3.1 load-bearing scrub invariant: the durable sink sits at/after Hub.publish,
which only ever sees post-_scrub payloads, so a raw MUD password is NEVER persisted.
Driven end-to-end against the stub MUD (the strongest possible guard)."""
import asyncio
import json
import unittest

from glyph_relay.history import HistoryStore
from glyph_relay.sessions import SessionManager, UserSession
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


class _OneShotConn:
    """A Connection double that hands ``_reader`` exactly one ``(text, events)``
    frame and then stops, so the scrub path can be driven without a live socket."""

    def __init__(self, frame):
        self._frame = frame

    async def receive(self):
        yield self._frame

    async def close(self):
        pass


class StructuredScrubInvariantTest(unittest.IsolatedAsyncioTestCase):
    async def test_structured_event_text_masked_before_publish(self):
        # A MUD can echo a just-typed password back inside an out-of-band GMCP package
        # (here a Comm.Channel ``text``). The relay must scrub the structured payload
        # BEFORE publish so the raw secret never reaches the Hub fan-out, the push
        # notifier, or the durable sink — the §3 invariant must hold for ALL kinds.
        secret = "throwaway-pw-structured-7461"
        sess = UserSession("h", 23, "a@x.com", secret, "Alice", use_tls=False)
        self.assertIn(secret, sess._secrets)   # password is a configured secret
        # GMCP (option byte 201) Comm.Channel frame carrying the secret in its text.
        body = json.dumps({"channel": "tells",
                           "text": "psst the password is {0}".format(secret)})
        payload = bytes([201]) + ("Comm.Channel " + body).encode("utf-8")
        conn = _OneShotConn(("", [("subneg", payload)]))
        await sess._reader(conn)
        structured = [data for _id, kind, data in sess.hub.backlog()
                      if kind == "structured"]
        self.assertEqual(len(structured), 1)
        blob = json.dumps(structured[0])
        self.assertNotIn(secret, blob)        # raw password absent from published event
        self.assertIn("********", blob)       # masked instead


if __name__ == "__main__":
    unittest.main()
