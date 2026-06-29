# SPDX-License-Identifier: Elastic-2.0
"""Per-target sessions, per-tenant quota + isolation, and the session-list
enumeration (spec §2.1/§2.3/§2.4). No real MUD: UserSession is faked.

NOTE on signature: ``email``/``password``/``character`` stay the first three
positional args (so the self-host call sites + regression suite are unchanged);
``tenant_id``/``target``/``connect_host`` are keyword-only additions. This adapts
the plan's positional ``create_user_session(tenant_id, ...)`` to the #140 baseline
that this repo extracted, where ``create_user_session(email, ...)`` already existed.
"""
import unittest

import glyph_relay.hub as hub_mod
import glyph_relay.sessions as sessions_mod
from glyph_relay.sessions import SessionManager, SessionLimitError


class _FakeUserSession:
    instances = []

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
        self.closed = False
        self.hub = hub_mod.Hub()
        _FakeUserSession.instances.append(self)

    async def start(self):
        pass

    def submit(self, text):
        return "ok"

    async def close(self):
        self.closed = True


class _FakeSessionBase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._orig = sessions_mod.UserSession
        sessions_mod.UserSession = _FakeUserSession
        _FakeUserSession.instances = []

    def tearDown(self):
        sessions_mod.UserSession = self._orig


class CreateSessionTargetTests(_FakeSessionBase):
    async def test_target_overrides_configured_host(self):
        mgr = SessionManager(host="default.example", port=4000)
        await mgr.create_user_session("e", "p", "c",
                                      target={"host": "other.example", "port": 5000, "tls": True})
        last = _FakeUserSession.instances[-1]
        self.assertEqual(last.host, "other.example")
        self.assertEqual(last.port, 5000)
        self.assertTrue(last.use_tls)

    async def test_no_target_uses_configured_default(self):
        mgr = SessionManager(host="default.example", port=4000, use_tls=False)
        await mgr.create_user_session("e", "p", "c")
        last = _FakeUserSession.instances[-1]
        self.assertEqual(last.host, "default.example")
        self.assertEqual(last.port, 4000)
        self.assertFalse(last.use_tls)

    async def test_pinned_connect_host_is_threaded(self):
        mgr = SessionManager(host="default.example", port=4000)
        await mgr.create_user_session("e", "p", "c",
                                      target={"host": "mud.example", "port": 4000, "tls": False},
                                      connect_host="8.8.8.8")
        self.assertEqual(_FakeUserSession.instances[-1].connect_host, "8.8.8.8")

    async def test_tenant_id_tags_session(self):
        mgr = SessionManager(host="h", port=1)
        await mgr.create_user_session("e", "p", "c", tenant_id="t-1")
        self.assertEqual(_FakeUserSession.instances[-1].tenant_id, "t-1")


class PerTenantQuotaTests(_FakeSessionBase):
    async def test_per_tenant_cap_enforced_independently(self):
        mgr = SessionManager(host="h", port=1, max_user_sessions=100,
                             max_sessions_per_tenant=2)
        await mgr.create_user_session("e", "p", "c", tenant_id="A")
        await mgr.create_user_session("e", "p", "c", tenant_id="A")
        with self.assertRaises(SessionLimitError):
            await mgr.create_user_session("e", "p", "c", tenant_id="A")  # A capped
        await mgr.create_user_session("e", "p", "c", tenant_id="B")      # B independent
        self.assertEqual(mgr.count_user_sessions("A"), 2)
        self.assertEqual(mgr.count_user_sessions("B"), 1)
        self.assertEqual(mgr.count_user_sessions(), 3)

    async def test_global_cap_still_applies(self):
        mgr = SessionManager(host="h", port=1, max_user_sessions=1,
                             max_sessions_per_tenant=10)
        await mgr.create_user_session("e", "p", "c", tenant_id="A")
        with self.assertRaises(SessionLimitError):
            await mgr.create_user_session("e", "p", "c", tenant_id="B")  # global cap hit

    async def test_no_per_tenant_cap_when_unset(self):
        mgr = SessionManager(host="h", port=1, max_user_sessions=10)  # no per-tenant
        for _ in range(5):
            await mgr.create_user_session("e", "p", "c", tenant_id="A")
        self.assertEqual(mgr.count_user_sessions("A"), 5)


class SessionListTests(_FakeSessionBase):
    async def test_lists_only_callers_own_tenant(self):
        mgr = SessionManager(host="h", port=4000, use_tls=False)
        ta = await mgr.create_user_session("a@x.com", "p", "Alice", tenant_id="A",
                                           target={"host": "g1", "port": 4001, "tls": False})
        await mgr.create_user_session("b@x.com", "p", "Bob", tenant_id="B")
        rows = mgr.list_tenant_sessions("A")
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["email"], "a@x.com")
        self.assertEqual(row["character"], "Alice")
        self.assertEqual(row["host"], "g1")
        self.assertEqual(row["port"], 4001)
        self.assertEqual(row["sessionKey"], ta)
        self.assertIn("createdAt", row)
        self.assertIn("lastEventId", row)
        # Never the password.
        self.assertNotIn("password", row)

    async def test_tenant_for_token(self):
        mgr = SessionManager(host="h", port=1)
        ta = await mgr.create_user_session("e", "p", "c", tenant_id="A")
        self.assertEqual(mgr.tenant_for_token(ta), "A")
        self.assertIsNone(mgr.tenant_for_token("nope"))

    async def test_empty_when_no_sessions_for_tenant(self):
        mgr = SessionManager(host="h", port=1)
        await mgr.create_user_session("e", "p", "c", tenant_id="A")
        self.assertEqual(mgr.list_tenant_sessions("Z"), [])


if __name__ == "__main__":
    unittest.main()
