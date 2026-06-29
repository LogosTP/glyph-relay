# SPDX-License-Identifier: Elastic-2.0
"""HTTP-level multi-tenant relay behaviour: broker-token auth + tenant tagging,
per-server target SSRF guard (§2.2), GET /sessions scoping (§2.4), ingest (§3.2),
and admin revoke/purge (§3.5). UserSession is faked (no real MUD socket)."""
import asyncio
import base64
import hashlib
import hmac as _hmac
import json
import unittest

import glyph_relay.sessions as sessions_mod
from glyph_relay.hub import Hub
from glyph_relay.history import HistoryStore
from glyph_relay.auth import BrokerTokenAuth
from glyph_relay.relay import Relay
from glyph_relay.sessions import SessionManager

KEY = b"test-shared-key"


def _token(tid, exp=9999999999):
    payload = base64.urlsafe_b64encode(
        json.dumps({"tid": tid, "exp": exp, "iat": 1},
                   separators=(",", ":")).encode()).rstrip(b"=").decode()
    si = "v1." + payload
    sig = base64.urlsafe_b64encode(
        _hmac.new(KEY, si.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    return si + "." + sig


class _FakeUserSession:
    def __init__(self, *, host, port, email, password, character, use_tls,
                 ca_file=None, ca_data=None, connect_host=None, history=None,
                 tenant_id=None, session_key=None):
        self.host = host
        self.port = port
        self.email = email
        self.password = password
        self.character = character
        self.use_tls = use_tls
        self.connect_host = connect_host
        self.tenant_id = tenant_id
        self.session_key = session_key
        self.created_at = None
        self.last_active = None
        # Mirror the real wiring so durable history + ingest are exercised.
        self.hub = Hub(sink=history, tenant_id=tenant_id, session_key=session_key)

    async def start(self):
        pass

    def submit(self, text):
        return "ok"

    async def close(self):
        pass


async def _request(port, method, route, *, headers=None, body=None, read_for=1.0):
    raw = b"" if body is None else json.dumps(body).encode()
    head = "{} {} HTTP/1.1\r\nHost: h\r\n".format(method, route)
    for k, v in (headers or {}).items():
        head += "{}: {}\r\n".format(k, v)
    head += "Content-Length: {}\r\n\r\n".format(len(raw))
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(head.encode() + raw)
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
    status = int(chunks.split(b" ", 2)[1]) if chunks else 0
    body_bytes = chunks.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in chunks else b""
    try:
        parsed = json.loads(body_bytes) if body_bytes else None
    except ValueError:
        parsed = None
    return status, parsed


class MultiTenantRelayTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self._orig = sessions_mod.UserSession
        sessions_mod.UserSession = _FakeUserSession
        self.history = HistoryStore(":memory:")
        self.denylist = set()
        self.mgr = SessionManager(host="default.mud", port=4000, use_tls=False,
                                  history=self.history, max_user_sessions=50,
                                  max_sessions_per_tenant=5)
        self.relay = Relay(manager=self.mgr, port=0,
                           authenticator=BrokerTokenAuth({"v1": KEY}, self.denylist),
                           admin_secret="adm", denylist=self.denylist,
                           history=self.history)
        await self.relay.start()
        self.port = self.relay.port

    async def asyncTearDown(self):
        await self.relay.close()
        await self.mgr.close_all()
        self.history.close()
        sessions_mod.UserSession = self._orig

    async def _new_session(self, tid, email="e@x.com", character="C", target=None):
        body = {"email": email, "password": "pw", "character": character}
        if target is not None:
            body["target"] = target
        status, data = await _request(self.port, "POST", "/session",
                                      headers={"X-Relay-Enroll": _token(tid)}, body=body)
        return status, data

    # --- auth + tenant tagging ---

    async def test_broker_token_mints_and_tags_tenant(self):
        status, data = await self._new_session("t-A")
        self.assertEqual(status, 200)
        self.assertIn("token", data)
        self.assertEqual(self.mgr.tenant_for_token(data["token"]), "t-A")

    async def test_bad_broker_token_is_403(self):
        status, _ = await _request(self.port, "POST", "/session",
                                   headers={"X-Relay-Enroll": "garbage"},
                                   body={"email": "e", "password": "p", "character": "c"})
        self.assertEqual(status, 403)

    # --- per-server target + SSRF (§2.1/§2.2) ---

    async def test_malformed_target_is_400(self):
        status, _ = await self._new_session(
            "t-A", target={"host": "mud.example", "port": "nope", "tls": True})
        self.assertEqual(status, 400)

    async def test_loopback_target_is_forbidden(self):
        # localhost resolves to 127.0.0.1 -> SSRF guard -> 403 forbidden_target.
        status, data = await self._new_session(
            "t-A", target={"host": "localhost", "port": 4000, "tls": False})
        self.assertEqual(status, 403)
        self.assertEqual(data.get("error"), "forbidden_target")

    async def test_allowed_target_threads_pin(self):
        # Patch the SSRF predicate to allow a public-looking target and pin an IP.
        import glyph_relay.targets as targets_mod
        orig = targets_mod.is_allowed_target
        targets_mod.is_allowed_target = lambda host, port, **kw: "203.0.113.9"
        try:
            status, data = await self._new_session(
                "t-A", target={"host": "mud.example", "port": 4000, "tls": True})
        finally:
            targets_mod.is_allowed_target = orig
        self.assertEqual(status, 200)
        sess = self.mgr.session_for_token(data["token"])
        self.assertEqual(sess.host, "mud.example")
        self.assertEqual(sess.connect_host, "203.0.113.9")
        self.assertTrue(sess.use_tls)

    # --- GET /sessions (§2.4) ---

    async def test_list_sessions_is_tenant_scoped(self):
        _, a = await self._new_session("t-A", email="a@x.com", character="Alice")
        await self._new_session("t-B", email="b@x.com", character="Bob")
        # Bearer of A's session sees only A.
        status, data = await _request(
            self.port, "GET", "/sessions",
            headers={"Authorization": "Bearer " + a["token"]})
        self.assertEqual(status, 200)
        self.assertEqual(len(data["sessions"]), 1)
        row = data["sessions"][0]
        self.assertEqual(row["email"], "a@x.com")
        self.assertEqual(row["character"], "Alice")
        self.assertEqual(row["sessionKey"], a["token"])
        self.assertNotIn("password", row)
        # Broker-token of B sees only B.
        status, data = await _request(self.port, "GET", "/sessions",
                                      headers={"X-Relay-Enroll": _token("t-B")})
        self.assertEqual(len(data["sessions"]), 1)
        self.assertEqual(data["sessions"][0]["email"], "b@x.com")

    async def test_list_sessions_unauthed_is_401(self):
        status, _ = await _request(self.port, "GET", "/sessions")
        self.assertEqual(status, 401)

    # --- ingest (§3.2) ---

    async def test_ingest_assigns_ids_and_persists(self):
        _, a = await self._new_session("t-A")
        key = a["token"]
        status, data = await _request(
            self.port, "POST", "/sessions/{}/ingest".format(key),
            headers={"Authorization": "Bearer " + key},
            body={"events": [{"kind": "output", "data": {"text": "x"}, "clientSeq": 1},
                             {"kind": "output", "data": {"text": "y"}, "clientSeq": 2}],
                  "after": 0})
        self.assertEqual(status, 200)
        self.assertEqual(data["accepted"], 2)
        rows = self.history.backlog("t-A", key)
        self.assertEqual([r[2]["text"] for r in rows], ["x", "y"])
        # Relay-assigned ids are monotonic (not the advisory clientSeq).
        self.assertTrue(rows[1][0] > rows[0][0])

    async def test_ingest_rejects_status_kind(self):
        _, a = await self._new_session("t-A")
        key = a["token"]
        status, data = await _request(
            self.port, "POST", "/sessions/{}/ingest".format(key),
            headers={"Authorization": "Bearer " + key},
            body={"events": [{"kind": "status", "data": {"state": "connected"}}]})
        self.assertEqual(status, 400)
        self.assertEqual(data.get("error"), "bad_kind")

    async def test_ingest_unknown_session_is_404(self):
        _, a = await self._new_session("t-A")
        status, _ = await _request(
            self.port, "POST", "/sessions/nope/ingest",
            headers={"Authorization": "Bearer " + a["token"]},
            body={"events": []})
        self.assertEqual(status, 404)

    async def test_ingest_cross_tenant_is_403(self):
        _, a = await self._new_session("t-A")
        _, b = await self._new_session("t-B")
        # B's credential trying to ingest into A's session -> 403.
        status, _ = await _request(
            self.port, "POST", "/sessions/{}/ingest".format(a["token"]),
            headers={"X-Relay-Enroll": _token("t-B")},
            body={"events": [{"kind": "output", "data": {"text": "x"}}]})
        self.assertEqual(status, 403)

    async def test_ingest_batch_is_monotonic_and_persisted(self):
        # Finding 2: the whole batch persists durably with ids strictly monotonic.
        _, a = await self._new_session("t-A")
        key = a["token"]
        batch = [{"kind": "output", "data": {"i": i}} for i in range(20)]
        status, data = await _request(
            self.port, "POST", "/sessions/{}/ingest".format(key),
            headers={"Authorization": "Bearer " + key}, body={"events": batch})
        self.assertEqual(status, 200)
        self.assertEqual(data["accepted"], 20)
        rows = self.history.backlog("t-A", key)
        ids = [r[0] for r in rows]
        self.assertEqual(ids, sorted(ids))
        self.assertEqual(len(set(ids)), 20)                  # all distinct + persisted
        self.assertEqual([r[2]["i"] for r in rows], list(range(20)))

    # --- admin (§3.5) ---

    async def test_admin_revoke_denylists_and_reaps(self):
        _, a = await self._new_session("t-A")
        self.assertEqual(self.mgr.count_user_sessions("t-A"), 1)
        status, data = await _request(self.port, "POST", "/admin/revoke",
                                      headers={"X-Relay-Admin": "adm"},
                                      body={"tenant_id": "t-A"})
        self.assertEqual(status, 200)
        self.assertEqual(data["reaped"], 1)
        self.assertEqual(self.mgr.count_user_sessions("t-A"), 0)
        self.assertIn("t-A", self.denylist)
        # A new broker token for the now-denylisted tenant is rejected.
        status, _ = await self._new_session("t-A")
        self.assertEqual(status, 403)

    async def test_admin_purge_deletes_history(self):
        _, a = await self._new_session("t-A")
        key = a["token"]
        await _request(self.port, "POST", "/sessions/{}/ingest".format(key),
                       headers={"Authorization": "Bearer " + key},
                       body={"events": [{"kind": "output", "data": {"text": "x"}}]})
        self.assertEqual(len(self.history.backlog("t-A", key)), 1)
        status, data = await _request(self.port, "POST", "/admin/purge",
                                      headers={"X-Relay-Admin": "adm"},
                                      body={"tenant_id": "t-A"})
        self.assertEqual(status, 200)
        self.assertEqual(data["deleted"], 1)
        self.assertEqual(self.history.backlog("t-A", key), [])

    async def test_admin_requires_secret(self):
        status, _ = await _request(self.port, "POST", "/admin/revoke",
                                   headers={"X-Relay-Admin": "wrong"},
                                   body={"tenant_id": "t-A"})
        self.assertEqual(status, 401)
        status, _ = await _request(self.port, "POST", "/admin/revoke",
                                   body={"tenant_id": "t-A"})
        self.assertEqual(status, 401)


class IngestRateLimitTest(unittest.IsolatedAsyncioTestCase):
    """Finding 1a: /ingest is rate-limited per tenant (429 over budget), ordered
    after auth (a rejected/foreign caller never consumes another tenant's budget)."""

    async def asyncSetUp(self):
        self._orig = sessions_mod.UserSession
        sessions_mod.UserSession = _FakeUserSession
        self.history = HistoryStore(":memory:")
        self.mgr = SessionManager(host="default.mud", port=4000, use_tls=False,
                                  history=self.history, max_sessions_per_tenant=5)
        # Budget of 2 ingest requests per very-wide window so the 3rd is denied.
        self.relay = Relay(manager=self.mgr, port=0,
                           authenticator=BrokerTokenAuth({"v1": KEY}, set()),
                           history=self.history, ingest_rate=2, ingest_window=1000.0)
        await self.relay.start()
        self.port = self.relay.port

    async def asyncTearDown(self):
        await self.relay.close()
        await self.mgr.close_all()
        self.history.close()
        sessions_mod.UserSession = self._orig

    async def _session(self, tid):
        _, data = await _request(self.port, "POST", "/session",
                                 headers={"X-Relay-Enroll": _token(tid)},
                                 body={"email": "e@x.com", "password": "pw", "character": "C"})
        return data["token"]

    async def _ingest(self, key, tid):
        return (await _request(
            self.port, "POST", "/sessions/{}/ingest".format(key),
            headers={"X-Relay-Enroll": _token(tid)},
            body={"events": [{"kind": "output", "data": {"text": "x"}}]}))[0]

    async def test_over_budget_is_429(self):
        key = await self._session("t-A")
        self.assertEqual(await self._ingest(key, "t-A"), 200)
        self.assertEqual(await self._ingest(key, "t-A"), 200)
        self.assertEqual(await self._ingest(key, "t-A"), 429)   # budget exhausted

    async def test_budget_is_per_tenant(self):
        ka = await self._session("t-A")
        kb = await self._session("t-B")
        # Drain A's budget; B is unaffected (noisy-neighbor isolation).
        self.assertEqual(await self._ingest(ka, "t-A"), 200)
        self.assertEqual(await self._ingest(ka, "t-A"), 200)
        self.assertEqual(await self._ingest(ka, "t-A"), 429)
        self.assertEqual(await self._ingest(kb, "t-B"), 200)
        self.assertEqual(await self._ingest(kb, "t-B"), 200)

    async def test_rate_after_auth_foreign_tenant_does_not_spend_budget(self):
        # A foreign tenant's rejected (403) ingest must not consume the owner's budget.
        ka = await self._session("t-A")
        await self._session("t-B")
        for _ in range(3):
            # t-B targeting A's session -> 403, never reaches the limiter.
            self.assertEqual(await self._ingest(ka, "t-B"), 403)
        # A's full budget is intact.
        self.assertEqual(await self._ingest(ka, "t-A"), 200)
        self.assertEqual(await self._ingest(ka, "t-A"), 200)
        self.assertEqual(await self._ingest(ka, "t-A"), 429)


class SelfHostAdminDisabledTest(unittest.IsolatedAsyncioTestCase):
    """In self-host (no admin_secret) the admin surface is simply absent -> 401."""

    async def test_admin_disabled_returns_401(self):
        relay = Relay(hub=Hub(capacity=4), submit=lambda t: "ok", token="static", port=0)
        await relay.start()
        try:
            status, _ = await _request(relay.port, "POST", "/admin/revoke",
                                       headers={"X-Relay-Admin": "anything"},
                                       body={"tenant_id": "x"})
            self.assertEqual(status, 401)
        finally:
            await relay.close()


if __name__ == "__main__":
    unittest.main()
