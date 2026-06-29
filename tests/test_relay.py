# SPDX-License-Identifier: Elastic-2.0
import asyncio
import unittest

from glyph_relay.hub import Hub
from glyph_relay.relay import parse_http_request, check_bearer, Relay


class HttpHelpersTest(unittest.TestCase):
    def test_parse_get_request_lowercases_headers(self):
        raw = b"GET /events?x=1 HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer t\r\n\r\n"
        method, path, headers = parse_http_request(raw)
        self.assertEqual(method, "GET")
        self.assertEqual(path, "/events?x=1")
        self.assertEqual(headers["authorization"], "Bearer t")
        self.assertEqual(headers["host"], "h")

    def test_parse_malformed_returns_none(self):
        self.assertIsNone(parse_http_request(b"garbage-no-space\r\n\r\n"))

    def test_check_bearer_accepts_exact_and_rejects_others(self):
        self.assertTrue(check_bearer({"authorization": "Bearer secret"}, "secret"))
        self.assertFalse(check_bearer({"authorization": "Bearer nope"}, "secret"))
        self.assertFalse(check_bearer({}, "secret"))
        self.assertFalse(check_bearer({"authorization": "secret"}, "secret"))

    def test_check_bearer_non_ascii_token_is_mismatch_not_crash(self):
        # A non-ASCII byte in the header (latin-1 decoded) must compare as a plain
        # mismatch -- never raise (hmac.compare_digest rejects non-ASCII str).
        self.assertFalse(check_bearer({"authorization": "Bearer \xff"}, "secret"))
        self.assertFalse(check_bearer({"authorization": "Bearer caf\xe9"}, "secret"))


async def _raw_request(port, request_bytes, read_for=0.5):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(request_bytes)
    await writer.drain()
    chunks = b""
    try:
        while True:
            chunk = await asyncio.wait_for(reader.read(4096), read_for)
            if not chunk:
                break
            chunks += chunk
    except asyncio.TimeoutError:
        pass
    writer.close()
    return chunks


class RelayServerTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.hub = Hub(capacity=10)
        self.submitted = []
        self.verdict = "ok"
        self.relay = Relay(self.hub, self._submit, token="tkn", port=0)
        await self.relay.start()
        self.port = self.relay.port

    async def asyncTearDown(self):
        await self.relay.close()

    def _submit(self, text):
        self.submitted.append(text)
        return self.verdict

    async def test_health_needs_no_auth(self):
        resp = await _raw_request(self.port, b"GET /health HTTP/1.1\r\nHost: h\r\n\r\n")
        self.assertIn(b"200 OK", resp)
        self.assertIn(b'"ok"', resp)

    async def test_command_requires_token(self):
        body = b'{"text":"say hi"}'
        req = (b"POST /command HTTP/1.1\r\nHost: h\r\nContent-Length: "
               + str(len(body)).encode() + b"\r\n\r\n" + body)
        resp = await _raw_request(self.port, req)
        self.assertIn(b"401", resp)
        self.assertEqual(self.submitted, [])

    async def test_command_accepted_returns_202_and_calls_submit(self):
        body = b'{"text":"say hi"}'
        req = (b"POST /command HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer tkn\r\n"
               b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
        resp = await _raw_request(self.port, req)
        self.assertIn(b"202", resp)
        self.assertEqual(self.submitted, ["say hi"])

    async def test_command_rejected_returns_409(self):
        self.verdict = "not_logged_in"
        body = b'{"text":"say hi"}'
        req = (b"POST /command HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer tkn\r\n"
               b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
        resp = await _raw_request(self.port, req)
        self.assertIn(b"409", resp)
        self.assertIn(b"not_logged_in", resp)

    async def test_events_streams_backlog_then_live(self):
        self.hub.publish("output", {"text": "old", "prompt": False})  # backlog id 1
        req = b"GET /events HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer tkn\r\n\r\n"
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        writer.write(req)
        await writer.drain()
        head = await asyncio.wait_for(reader.read(4096), 1.0)
        self.assertIn(b"text/event-stream", head)
        self.assertIn(b'"text":"old"', head)
        self.hub.publish("output", {"text": "new", "prompt": True})   # live id 2
        live = await asyncio.wait_for(reader.read(4096), 1.0)
        self.assertIn(b'"text":"new"', live)
        self.assertIn(b"id: 2", live)
        writer.close()

    async def test_structured_event_is_forwarded_and_resumes(self):
        # A parsed GMCP package rides the same SSE stream as a "structured" event, and
        # a reconnect with Last-Event-ID replays it, so out-of-band state survives a
        # dropped connection (#59 criteria: forward + resume).
        vitals = {"type": "vitals", "data": {"gauges": {"hp": 100.0}, "fields": {}}}
        self.hub.publish("structured", vitals)   # backlog id 1
        live = await _raw_request(
            self.port,
            b"GET /events HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer tkn\r\n\r\n")
        self.assertIn(b"event: structured", live)
        self.assertIn(b'"type":"vitals"', live)
        self.assertIn(b"id: 1", live)

        # A fresh attach resuming from before it replays the structured backlog.
        replay = await _raw_request(
            self.port,
            b"GET /events HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer tkn\r\n"
            b"Last-Event-ID: 0\r\n\r\n")
        self.assertIn(b"event: structured", replay)
        self.assertIn(b'"type":"vitals"', replay)

    async def test_non_dict_json_body_returns_400_no_crash(self):
        body = b"5"  # valid JSON, but not an object -> must be 400, not a TypeError
        req = (b"POST /command HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer tkn\r\n"
               b"Content-Length: 1\r\n\r\n" + body)
        resp = await _raw_request(self.port, req)
        self.assertIn(b"400", resp)
        self.assertEqual(self.submitted, [])

    async def test_negative_content_length_returns_400_no_crash(self):
        req = (b"POST /command HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer tkn\r\n"
               b"Content-Length: -1\r\n\r\n")
        resp = await _raw_request(self.port, req)
        self.assertIn(b"400", resp)
        self.assertEqual(self.submitted, [])

    async def test_unknown_route_returns_404(self):
        req = b"GET /nope HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer tkn\r\n\r\n"
        resp = await _raw_request(self.port, req)
        self.assertIn(b"404", resp)

    async def test_high_last_event_id_does_not_blackout_live_events(self):
        # Fresh hub (ids start at 1); client resumes from a stale, much higher id
        # (as after a daemon restart). Live events must still be delivered.
        req = (b"GET /events HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer tkn\r\n"
               b"Last-Event-ID: 5000\r\n\r\n")
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        writer.write(req)
        await writer.drain()
        await asyncio.wait_for(reader.read(4096), 1.0)  # response head
        self.hub.publish("output", {"text": "live-after-restart", "prompt": False})
        live = await asyncio.wait_for(reader.read(4096), 1.0)
        self.assertIn(b"live-after-restart", live)
        writer.close()

    async def test_attach_replays_current_status_even_past_last_event_id(self):
        # A reconnecting client whose Last-Event-ID skipped past the status event
        # must still learn the current connection state on attach (else its input
        # stays disabled). Status id 1 is below since_id=2, yet must be re-sent.
        self.hub.publish("status", {"state": "connected"})           # id 1
        self.hub.publish("output", {"text": "x", "prompt": False})   # id 2
        req = (b"GET /events HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer tkn\r\n"
               b"Last-Event-ID: 2\r\n\r\n")
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        writer.write(req)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(4096), 1.0)
        self.assertIn(b'"state":"connected"', data)
        writer.close()

    async def test_two_subscribers_both_receive_live_event(self):
        req = b"GET /events HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer tkn\r\n\r\n"
        r1, w1 = await asyncio.open_connection("127.0.0.1", self.port)
        r2, w2 = await asyncio.open_connection("127.0.0.1", self.port)
        for w in (w1, w2):
            w.write(req)
            await w.drain()
        await asyncio.wait_for(r1.read(4096), 1.0)
        await asyncio.wait_for(r2.read(4096), 1.0)
        self.hub.publish("output", {"text": "broadcast", "prompt": False})
        d1 = await asyncio.wait_for(r1.read(4096), 1.0)
        d2 = await asyncio.wait_for(r2.read(4096), 1.0)
        self.assertIn(b"broadcast", d1)
        self.assertIn(b"broadcast", d2)
        w1.close()
        w2.close()


class RelayKeepaliveTest(unittest.IsolatedAsyncioTestCase):
    async def test_keepalive_comment_on_idle_stream(self):
        hub = Hub(capacity=10)
        relay = Relay(hub, lambda t: "ok", token="tkn", port=0, keepalive=0.05)
        await relay.start()
        try:
            req = b"GET /events HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer tkn\r\n\r\n"
            reader, writer = await asyncio.open_connection("127.0.0.1", relay.port)
            writer.write(req)
            await writer.drain()
            data = b""
            for _ in range(5):
                data += await asyncio.wait_for(reader.read(4096), 1.0)
                if b": keepalive" in data:
                    break
            self.assertIn(b": keepalive", data)
            writer.close()
        finally:
            await relay.close()


from glyph_relay.sessions import SessionManager
from stub.stub_server import Room, handle


class RelayMultiSessionTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        room = Room()
        self.mud = await asyncio.start_server(lambda r, w: handle(r, w, room), "127.0.0.1", 0)
        mud_port = self.mud.sockets[0].getsockname()[1]
        self.mgr = SessionManager(host="127.0.0.1", port=mud_port, use_tls=False, max_user_sessions=5)
        self.relay = Relay(manager=self.mgr, port=0)
        await self.relay.start()
        self.port = self.relay.port

    async def asyncTearDown(self):
        await self.relay.close()
        await self.mgr.close_all()
        self.mud.close(); await self.mud.wait_closed()

    async def _post(self, path, body, token=None):
        raw = body.encode()
        head = ("POST %s HTTP/1.1\r\nHost: h\r\n" % path)
        if token:
            head += "Authorization: Bearer %s\r\n" % token
        head += "Content-Length: %d\r\n\r\n" % len(raw)
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        writer.write(head.encode() + raw); await writer.drain()
        resp = await asyncio.wait_for(reader.read(4096), 2.0)
        writer.close()
        return resp

    async def test_post_session_mints_token(self):
        resp = await self._post("/session", '{"email":"a@x.com","password":"pw","character":"A"}')
        self.assertIn(b"200", resp)
        self.assertIn(b'"token"', resp)
        self.assertNotIn(b"pw", resp.split(b"\r\n\r\n", 1)[0])  # token line only; no creds echoed

    async def test_unknown_token_is_401_on_command(self):
        body = b'{"text":"look"}'
        head = (b"POST /command HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer nope\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        writer.write(head); await writer.drain()
        resp = await asyncio.wait_for(reader.read(4096), 2.0); writer.close()
        self.assertIn(b"401", resp)

    async def test_token_isolation_command_routes_to_own_session(self):
        import json
        ra = await self._post("/session", '{"email":"a@x.com","password":"pwa","character":"Alice"}')
        rb = await self._post("/session", '{"email":"b@x.com","password":"pwb","character":"Bob"}')
        ta = json.loads(ra.split(b"\r\n\r\n", 1)[1])["token"]
        tb = json.loads(rb.split(b"\r\n\r\n", 1)[1])["token"]
        self.assertNotEqual(ta, tb)
        # Both tokens are accepted by /command only for their own session.
        for tok in (ta, tb):
            r = await self._post("/command", '{"text":"look"}', token=tok)
            self.assertTrue(b"202" in r or b"409" in r)  # accepted or gated, never 401
        # A made-up token is rejected.
        r = await self._post("/command", '{"text":"look"}', token="forged")
        self.assertIn(b"401", r)

    async def test_logout_tears_down_session(self):
        import json
        r = await self._post("/session", '{"email":"a@x.com","password":"pw","character":"A"}')
        tok = json.loads(r.split(b"\r\n\r\n", 1)[1])["token"]
        self.assertIsNotNone(self.mgr.resolve(tok))
        lr = await self._post("/logout", "", token=tok)
        self.assertTrue(b"200" in lr or b"204" in lr)
        self.assertIsNone(self.mgr.resolve(tok))   # gone; creds dropped inside unregister


class RelayCapAndBootstrapTest(unittest.IsolatedAsyncioTestCase):
    """Isolated tests for 503-capacity-cap and 403-bootstrap-logout paths.

    No real MUD needed: the 503 test uses max_user_sessions=0 (SessionLimitError
    fires before any connection attempt), and the 403 test uses the legacy shim
    which never opens a socket.
    """

    async def test_post_session_over_cap_returns_503(self):
        # A manager at capacity rejects new sessions with 503.
        import json
        from glyph_relay.sessions import SessionManager
        mgr = SessionManager(host="127.0.0.1", port=1, use_tls=False, max_user_sessions=0)
        relay = Relay(manager=mgr, port=0)
        await relay.start()
        try:
            raw = b'{"email":"a@x.com","password":"pw","character":"A"}'
            head = (b"POST /session HTTP/1.1\r\nHost: h\r\nContent-Length: "
                    + str(len(raw)).encode() + b"\r\n\r\n" + raw)
            r, w = await asyncio.open_connection("127.0.0.1", relay.port)
            w.write(head); await w.drain()
            resp = await asyncio.wait_for(r.read(4096), 2.0); w.close()
            self.assertIn(b"503", resp)
        finally:
            await relay.close()
            await mgr.close_all()

    async def test_logout_bootstrap_token_is_403(self):
        relay = Relay(hub=Hub(capacity=4), submit=lambda t: "ok", token="static", port=0)
        await relay.start()
        try:
            head = (b"POST /logout HTTP/1.1\r\nHost: h\r\n"
                    b"Authorization: Bearer static\r\nContent-Length: 0\r\n\r\n")
            r, w = await asyncio.open_connection("127.0.0.1", relay.port)
            w.write(head); await w.drain()
            resp = await asyncio.wait_for(r.read(4096), 2.0); w.close()
            self.assertIn(b"403", resp)
            # Bootstrap session must survive — still resolvable.
            self.assertIsNotNone(relay.manager.resolve("static"))
        finally:
            await relay.close()


class SlidingWindowRateLimiterTest(unittest.TestCase):
    """Pure, clock-injected windowing logic (no relay/MUD)."""

    def test_allows_up_to_limit_then_denies(self):
        from glyph_relay.relay import SlidingWindowRateLimiter
        rl = SlidingWindowRateLimiter(limit=3, window=60)
        self.assertTrue(rl.allow(now=100.0))
        self.assertTrue(rl.allow(now=100.1))
        self.assertTrue(rl.allow(now=100.2))
        self.assertFalse(rl.allow(now=100.3))   # 4th within the window is denied

    def test_window_slides_and_frees_budget(self):
        from glyph_relay.relay import SlidingWindowRateLimiter
        rl = SlidingWindowRateLimiter(limit=2, window=10)
        self.assertTrue(rl.allow(now=0.0))
        self.assertTrue(rl.allow(now=1.0))
        self.assertFalse(rl.allow(now=2.0))      # budget full
        self.assertTrue(rl.allow(now=11.5))      # event at t=0 aged out of the window
        self.assertTrue(rl.allow(now=11.6))      # event at t=1 aged out too

    def test_denied_requests_do_not_consume_budget(self):
        # A denied attempt must NOT record itself; otherwise a steady flood keeps
        # pushing the window forward and the limiter never recovers.
        from glyph_relay.relay import SlidingWindowRateLimiter
        rl = SlidingWindowRateLimiter(limit=1, window=10)
        self.assertTrue(rl.allow(now=0.0))
        self.assertFalse(rl.allow(now=1.0))
        self.assertFalse(rl.allow(now=2.0))
        self.assertTrue(rl.allow(now=10.5))      # only the t=0 event existed; aged out


class RelaySessionGatingTest(unittest.IsolatedAsyncioTestCase):
    """Per-user enrollment (403) and rate-limit (429) gates on POST /session (#140).

    max_user_sessions=0 means any request that PASSES the gates returns 503 (cap)
    without a real MUD — so a 503 proves the request got past the gate under test."""

    def _registry(self):
        import os
        import tempfile
        from glyph_relay.enrollment import EnrollmentRegistry
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        # Low iteration count keeps these async tests fast.
        return EnrollmentRegistry(os.path.join(d.name, "e.db"), iters=1000)

    async def _make_relay(self, **relay_kw):
        from glyph_relay.sessions import SessionManager
        registry = relay_kw.get("enroll_registry")
        mgr = SessionManager(host="127.0.0.1", port=1, use_tls=False, max_user_sessions=0,
                             enroll_registry=registry)
        relay = Relay(manager=mgr, port=0, **relay_kw)
        await relay.start()
        self.addAsyncCleanup(mgr.close_all)
        self.addAsyncCleanup(relay.close)
        return relay

    async def _post_session(self, port, *, enroll=None):
        raw = b'{"email":"a@x.com","password":"pw","character":"A"}'
        head = b"POST /session HTTP/1.1\r\nHost: h\r\n"
        if enroll is not None:
            head += b"X-Relay-Enroll: " + enroll.encode() + b"\r\n"
        head += b"Content-Length: " + str(len(raw)).encode() + b"\r\n\r\n" + raw
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(head); await w.drain()
        resp = await asyncio.wait_for(r.read(4096), 2.0); w.close()
        return resp

    async def test_no_enroll_registry_means_endpoint_is_open(self):
        relay = await self._make_relay()                    # default: no registry, no rate
        self.assertIn(b"503", await self._post_session(relay.port))   # open -> cap -> 503

    async def test_valid_credential_passes_gate(self):
        reg = self._registry()
        ident, secret = reg.add("phone", now=1.0)
        relay = await self._make_relay(enroll_registry=reg)
        # Valid id.secret passes the gate -> reaches the (capped) manager -> 503.
        self.assertIn(b"503", await self._post_session(
            relay.port, enroll="{0}.{1}".format(ident, secret)))

    async def test_missing_and_wrong_and_malformed_credentials_rejected(self):
        reg = self._registry()
        ident, secret = reg.add("phone", now=1.0)
        relay = await self._make_relay(enroll_registry=reg)
        for cred in (None, "wrong", "{0}.bad".format(ident), "nodot", "deadbeef.x"):
            resp = await self._post_session(relay.port, enroll=cred)
            self.assertIn(b"403", resp)        # rejected
            self.assertNotIn(b"503", resp)     # never reached the manager

    async def test_revoked_credential_rejected(self):
        reg = self._registry()
        ident, secret = reg.add("phone", now=1.0)
        reg.revoke(ident, now=2.0)
        relay = await self._make_relay(enroll_registry=reg)
        resp = await self._post_session(relay.port, enroll="{0}.{1}".format(ident, secret))
        self.assertIn(b"403", resp)
        self.assertNotIn(b"503", resp)

    async def test_expired_credential_rejected(self):
        reg = self._registry()
        # expires in the past relative to wall-clock now -> rejected.
        ident, secret = reg.add("phone", expires_at=1.0, now=0.5)
        relay = await self._make_relay(enroll_registry=reg)
        resp = await self._post_session(relay.port, enroll="{0}.{1}".format(ident, secret))
        self.assertIn(b"403", resp)
        self.assertNotIn(b"503", resp)

    async def test_enroll_gate_fires_before_rate_limit(self):
        # A rejected credential returns 403 even when the rate budget is exhausted:
        # the gate runs before the limiter, so 403 wins over 429 (no budget consumed).
        reg = self._registry()
        reg.add("phone", now=1.0)
        relay = await self._make_relay(enroll_registry=reg, session_rate=1,
                                       session_window=1000)
        for _ in range(3):
            self.assertIn(b"403", await self._post_session(relay.port, enroll="bad.cred"))

    async def test_rate_limit_returns_429_after_budget(self):
        relay = await self._make_relay(session_rate=1, session_window=1000)
        # 1st attempt passes the limiter, then hits the cap -> 503 (token consumed).
        self.assertIn(b"503", await self._post_session(relay.port))
        # 2nd within the window is rate-limited before any create attempt -> 429.
        self.assertIn(b"429", await self._post_session(relay.port))


if __name__ == "__main__":
    unittest.main()
