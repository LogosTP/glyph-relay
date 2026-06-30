# SPDX-License-Identifier: Elastic-2.0
"""Per-tenant reaping for admin revoke (spec §3.5). The HTTP admin routes are
exercised in test_relay_multitenant.py; this covers the pure SessionManager method."""
import unittest

import glyph_relay.hub as hub_mod
import glyph_relay.sessions as sessions_mod
from glyph_relay.sessions import SessionManager


class _FakeUserSession:
    def __init__(self, *, host, port, email, password, character, use_tls,
                 ca_file=None, ca_data=None, connect_host=None, history=None,
                 tenant_id=None, session_key=None, push_notifier=None):
        self.host = host
        self.port = port
        self.email = email
        self.password = password
        self.character = character
        self.use_tls = use_tls
        self.tenant_id = tenant_id
        self.session_key = session_key
        self.created_at = None
        self.last_active = None
        self.closed = False
        self.hub = hub_mod.Hub()

    async def start(self):
        pass

    def submit(self, text):
        return "ok"

    async def close(self):
        self.closed = True


class ReapTenantTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._orig = sessions_mod.UserSession
        sessions_mod.UserSession = _FakeUserSession

    def tearDown(self):
        sessions_mod.UserSession = self._orig

    async def test_reap_tenant_closes_only_that_tenant(self):
        mgr = SessionManager(host="h", port=1, max_sessions_per_tenant=10)
        await mgr.create_user_session("e", "p", "c", tenant_id="A")
        await mgr.create_user_session("e", "p", "c", tenant_id="A")
        await mgr.create_user_session("e", "p", "c", tenant_id="B")
        n = await mgr.reap_tenant("A")
        self.assertEqual(n, 2)
        self.assertEqual(mgr.count_user_sessions("A"), 0)
        self.assertEqual(mgr.count_user_sessions("B"), 1)

    async def test_reap_unknown_tenant_is_noop(self):
        mgr = SessionManager(host="h", port=1)
        await mgr.create_user_session("e", "p", "c", tenant_id="A")
        self.assertEqual(await mgr.reap_tenant("Z"), 0)
        self.assertEqual(mgr.count_user_sessions(), 1)


if __name__ == "__main__":
    unittest.main()
