# SPDX-License-Identifier: Elastic-2.0
"""Coarse push-trigger classification + best-effort notify (spec §4.2.1).

Covers: ``classify_event`` for every kind (disconnect / tell-vs-channel split /
highlight, plus the skips: status connected/reconnecting, echo, other structured
types, empty output); ``_snippet`` truncation; ``PushNotifier`` gating + rate-limit
shedding + exact payload fields via an injected dispatch; ``post_notify`` wire format
against a local ``http.server`` AND its best-effort swallow of a dead-port error;
``Hub`` notifier threading (persist gate + error isolation); and ``SessionManager`` /
``UserSession`` / ``config`` threading of the notifier."""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

import glyph_relay.hub as hub_mod
import glyph_relay.sessions as sessions_mod
from glyph_relay.config import build_relay
from glyph_relay.hub import Hub
from glyph_relay.push import classify_event, _snippet, post_notify, PushNotifier
from glyph_relay.sessions import SessionManager, UserSession


class ClassifyEventTests(unittest.TestCase):
    def test_status_disconnected_is_disconnect_no_text(self):
        self.assertEqual(classify_event("status", {"state": "disconnected"}),
                         ("disconnect", None))

    def test_status_connected_skipped(self):
        self.assertEqual(classify_event("status", {"state": "connected"}),
                         (None, None))

    def test_status_reconnecting_skipped(self):
        self.assertEqual(classify_event("status", {"state": "reconnecting"}),
                         (None, None))

    def test_comm_tell_channel_when_name_contains_tell(self):
        ev = {"type": "commChannel", "data": {"channel": "Tells", "text": "hi there"}}
        self.assertEqual(classify_event("structured", ev), ("tell", "hi there"))

    def test_comm_non_tell_is_channel(self):
        ev = {"type": "commChannel", "data": {"channel": "gossip", "text": "yo"}}
        self.assertEqual(classify_event("structured", ev), ("channel", "yo"))

    def test_comm_missing_text_is_none_snippet(self):
        ev = {"type": "commChannel", "data": {"channel": "tell"}}
        self.assertEqual(classify_event("structured", ev), ("tell", None))

    def test_structured_other_type_skipped(self):
        self.assertEqual(classify_event("structured", {"type": "mssp", "data": {}}),
                         (None, None))

    def test_output_nonempty_is_highlight(self):
        self.assertEqual(classify_event("output", {"text": "You are bleeding."}),
                         ("highlight", "You are bleeding."))

    def test_output_empty_or_whitespace_text_skipped(self):
        self.assertEqual(classify_event("output", {"text": ""}), (None, None))
        self.assertEqual(classify_event("output", {"text": "   "}), (None, None))
        self.assertEqual(classify_event("output", {"prompt": True}), (None, None))

    def test_echo_skipped(self):
        self.assertEqual(classify_event("echo", {"text": "look"}), (None, None))

    def test_unknown_kind_skipped(self):
        self.assertEqual(classify_event("prompt", {"text": "x"}), (None, None))

    def test_non_dict_data_skipped(self):
        self.assertEqual(classify_event("status", None), (None, None))
        self.assertEqual(classify_event("structured", "x"), (None, None))
        self.assertEqual(classify_event("output", None), (None, None))


class SnippetTests(unittest.TestCase):
    def test_falsy_is_none(self):
        self.assertIsNone(_snippet(""))
        self.assertIsNone(_snippet(None))
        self.assertIsNone(_snippet(0))

    def test_truncates_to_256(self):
        self.assertEqual(_snippet("a" * 300), "a" * 256)
        self.assertEqual(len(_snippet("b" * 1000)), 256)

    def test_coerces_to_str(self):
        self.assertEqual(_snippet(12345), "12345")


class PushNotifierGatingTests(unittest.TestCase):
    def setUp(self):
        self.captured = []
        self.n = PushNotifier("http://x/notify", "sek",
                              dispatch=self.captured.append)

    def test_classify_gates_non_push_events(self):
        self.n("t", "s", 5, "echo", {"text": "look"})
        self.n("t", "s", 6, "status", {"state": "connected"})
        self.n("t", "s", 7, "structured", {"type": "mssp", "data": {}})
        self.n("t", "s", 8, "output", {"text": "   "})
        self.assertEqual(self.captured, [])

    def test_payload_fields_exact_with_event_id_passthrough(self):
        self.n("tA", "sK", 42, "structured",
               {"type": "commChannel", "data": {"channel": "Tells", "text": "hey"}})
        self.assertEqual(len(self.captured), 1)
        p = self.captured[0]
        self.assertEqual(p["tenant_id"], "tA")
        self.assertEqual(p["session_key"], "sK")
        self.assertEqual(p["event_id"], 42)        # relay-assigned id passthrough
        self.assertEqual(p["kind"], "structured")
        self.assertEqual(p["category"], "tell")
        self.assertEqual(p["text"], "hey")
        self.assertIsInstance(p["ts"], float)
        self.assertEqual(set(p), {"tenant_id", "session_key", "event_id",
                                  "kind", "category", "text", "ts"})

    def test_disconnect_payload_text_is_null(self):
        self.n("t", "s", 1, "status", {"state": "disconnected"})
        self.assertEqual(self.captured[0]["category"], "disconnect")
        self.assertIsNone(self.captured[0]["text"])


class PushNotifierRateLimitTests(unittest.TestCase):
    def test_rate_limit_sheds_beyond_cap(self):
        captured = []
        n = PushNotifier("http://x", "s", rate=3, window=60.0,
                         dispatch=captured.append)
        for i in range(10):
            n("t", "s", i, "output", {"text": "line {0}".format(i)})
        self.assertEqual(len(captured), 3)
        # The first three event ids pass; the rest are shed within the window.
        self.assertEqual([p["event_id"] for p in captured], [0, 1, 2])

    def test_rate_limit_is_per_tenant_session(self):
        captured = []
        n = PushNotifier("http://x", "s", rate=1, window=60.0,
                         dispatch=captured.append)
        n("A", "s", 1, "output", {"text": "x"})
        n("A", "s", 2, "output", {"text": "y"})   # shed: same (tenant, session)
        n("B", "s", 3, "output", {"text": "z"})   # different tenant: own budget
        self.assertEqual([p["tenant_id"] for p in captured], ["A", "B"])

    def test_rate_zero_disables_limiter(self):
        captured = []
        n = PushNotifier("http://x", "s", rate=0, dispatch=captured.append)
        for i in range(50):
            n("t", "s", i, "output", {"text": "x"})
        self.assertEqual(len(captured), 50)


class _NotifyHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        self.server.captured.append({
            "path": self.path,
            "notify_header": self.headers.get("X-Relay-Notify"),
            "content_type": self.headers.get("Content-Type"),
            "body": json.loads(body.decode("utf-8")),
        })
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"sent"}')

    def log_message(self, *args):
        pass  # keep the test output clean


class PostNotifyTests(unittest.TestCase):
    def test_posts_notify_header_and_json_body(self):
        server = HTTPServer(("127.0.0.1", 0), _NotifyHandler)
        server.captured = []
        t = threading.Thread(target=server.handle_request)
        t.start()
        try:
            url = "http://127.0.0.1:{0}/v1/push/notify".format(
                server.server_address[1])
            payload = {"tenant_id": "t", "session_key": "s", "event_id": 9,
                       "kind": "output", "category": "highlight",
                       "text": "hi", "ts": 1.0}
            post_notify(url, "shared-secret", payload, timeout=5.0)
            t.join(5)
        finally:
            server.server_close()
        self.assertEqual(len(server.captured), 1)
        cap = server.captured[0]
        self.assertEqual(cap["path"], "/v1/push/notify")
        self.assertEqual(cap["notify_header"], "shared-secret")
        self.assertEqual(cap["content_type"], "application/json")
        self.assertEqual(cap["body"], payload)

    def test_swallows_connection_error_to_dead_port(self):
        # Nothing listening on port 1: post_notify must NOT raise (best-effort).
        post_notify("http://127.0.0.1:1/notify", "s", {"x": 1}, timeout=0.5)


class HubNotifierTests(unittest.TestCase):
    def test_notifier_called_for_persist_true(self):
        seen = []
        hub = Hub(capacity=10, tenant_id="T", session_key="S",
                  notifier=lambda *a: seen.append(a))
        eid = hub.publish("output", {"text": "hello"})
        self.assertEqual(seen, [("T", "S", eid, "output", {"text": "hello"})])

    def test_notifier_not_called_for_persist_false(self):
        seen = []
        hub = Hub(capacity=10, tenant_id="T", session_key="S",
                  notifier=lambda *a: seen.append(a))
        hub.publish("output", {"text": "ingest backfill"}, persist=False)
        self.assertEqual(seen, [])

    def test_notifier_exception_never_breaks_publish(self):
        def boom(*a):
            raise RuntimeError("notifier bug")
        hub = Hub(capacity=10, notifier=boom)
        eid = hub.publish("output", {"text": "x"})   # must not raise
        self.assertEqual(eid, 1)
        self.assertEqual([e[0] for e in hub.backlog()], [1])


class _CapSession:
    """Captures the push_notifier threaded through create_user_session, mirroring
    the real UserSession's Hub wiring."""
    last = None

    def __init__(self, *, host, port, email, password, character, use_tls,
                 ca_file=None, ca_data=None, connect_host=None, history=None,
                 tenant_id=None, session_key=None, push_notifier=None):
        self.host = host
        self.port = port
        self.email = email
        self.password = password
        self.character = character
        self.use_tls = use_tls
        self.connect_host = connect_host
        self.tenant_id = tenant_id
        self.session_key = session_key
        self.push_notifier = push_notifier
        self.created_at = None
        self.last_active = None
        self.closed = False
        self.hub = hub_mod.Hub(notifier=push_notifier)
        _CapSession.last = self

    async def start(self):
        pass

    def submit(self, text):
        return "ok"

    async def close(self):
        self.closed = True


class SessionManagerNotifierTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._orig = sessions_mod.UserSession
        sessions_mod.UserSession = _CapSession
        _CapSession.last = None

    def tearDown(self):
        sessions_mod.UserSession = self._orig

    async def test_push_notifier_threaded_into_session_and_hub(self):
        def notifier(*a):
            pass
        mgr = SessionManager(host="h", port=1, push_notifier=notifier)
        await mgr.create_user_session("e", "p", "c", tenant_id="A")
        self.assertIs(_CapSession.last.push_notifier, notifier)
        self.assertIs(_CapSession.last.hub.notifier, notifier)

    async def test_default_push_notifier_is_none(self):
        mgr = SessionManager(host="h", port=1)
        await mgr.create_user_session("e", "p", "c")
        self.assertIsNone(_CapSession.last.push_notifier)


class UserSessionNotifierTests(unittest.TestCase):
    def test_real_user_session_threads_notifier_into_hub(self):
        def notifier(*a):
            pass
        sess = UserSession("h", 23, "e@x.com", "pw", "Char",
                           use_tls=False, push_notifier=notifier)
        self.assertIs(sess.hub.notifier, notifier)

    def test_real_user_session_default_hub_notifier_none(self):
        sess = UserSession("h", 23, "e@x.com", "pw", "Char", use_tls=False)
        self.assertIsNone(sess.hub.notifier)


class ConfigPushTests(unittest.TestCase):
    def test_hosted_builds_push_notifier_when_env_set(self):
        env = {"SHARED_HMAC_KEY": "k", "SHARED_HMAC_KID": "v1",
               "RELAY_ADMIN_SECRET": "adm", "HISTORY_DB": ":memory:",
               "RELAY_NOTIFY_URL": "http://127.0.0.1:8080/v1/push/notify",
               "RELAY_NOTIFY_SECRET": "shh"}
        r = build_relay("hosted", env)
        self.addCleanup(r.history.close)
        self.assertIsInstance(r.manager.push_notifier, PushNotifier)

    def test_hosted_no_push_when_secret_unset(self):
        env = {"SHARED_HMAC_KEY": "k", "SHARED_HMAC_KID": "v1",
               "RELAY_ADMIN_SECRET": "adm", "HISTORY_DB": ":memory:",
               "RELAY_NOTIFY_URL": "http://127.0.0.1:8080/v1/push/notify"}
        r = build_relay("hosted", env)
        self.addCleanup(r.history.close)
        self.assertIsNone(r.manager.push_notifier)

    def test_selfhost_never_builds_push_notifier(self):
        r = build_relay("selfhost", {"RELAY_NOTIFY_URL": "http://x",
                                     "RELAY_NOTIFY_SECRET": "shh"})
        self.assertIsNone(r.manager.push_notifier)


if __name__ == "__main__":
    unittest.main()
