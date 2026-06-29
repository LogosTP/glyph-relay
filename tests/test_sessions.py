# tests/test_sessions.py
# SPDX-License-Identifier: Elastic-2.0
import asyncio
import hmac
import unittest

from glyph_relay.sessions import scrub_secrets, drain_queue, UserSession
from glyph_relay.sessions import SessionManager, SessionLimitError
from stub.stub_server import Room, handle


class HelpersTest(unittest.TestCase):
    def test_scrub_replaces_each_secret(self):
        self.assertEqual(scrub_secrets({"pw"}, "my pw here"), "my ******** here")
        self.assertEqual(scrub_secrets({"pw", "secret"}, "pw and secret"),
                         "******** and ********")

    def test_scrub_ignores_empty_secret(self):
        # An empty secret must not turn every gap into masks.
        self.assertEqual(scrub_secrets({""}, "abc"), "abc")

    def test_scrub_no_secrets_is_identity(self):
        self.assertEqual(scrub_secrets(set(), "abc"), "abc")


class DrainTest(unittest.IsolatedAsyncioTestCase):
    async def test_drain_empties_queue(self):
        q = asyncio.Queue()
        q.put_nowait(("claude", "a", "a"))
        q.put_nowait(("claude", "b", "b"))
        drain_queue(q)
        self.assertTrue(q.empty())

    async def test_drain_on_empty_is_noop(self):
        q = asyncio.Queue()
        drain_queue(q)  # must not raise
        self.assertTrue(q.empty())


async def _wait(predicate, timeout=5.0):
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.05)
    return False


class UserSessionTest(unittest.IsolatedAsyncioTestCase):
    async def _stub(self):
        room = Room()
        server = await asyncio.start_server(lambda r, w: handle(r, w, room), "127.0.0.1", 0)
        return server, server.sockets[0].getsockname()[1]

    async def test_logs_in_and_submits_through_hub(self):
        server, port = await self._stub()
        sess = UserSession(host="127.0.0.1", port=port,
                           email="tester@example.com", password="throwaway-pw",
                           character="Tester", use_tls=False)
        await sess.start()
        try:
            # The gate opens after login; submit then see it in the hub backlog.
            self.assertTrue(await _wait(lambda: sess.submit("say hi") == "ok"))
            def saw_output():
                return any(kind == "output" and "hi" in data.get("text", "")
                           for _id, kind, data in sess.hub.backlog())
            self.assertTrue(await _wait(saw_output))
            # The password must never appear in any hub event.
            joined = "".join(str(data) for _i, _k, data in sess.hub.backlog())
            self.assertNotIn("throwaway-pw", joined)
        finally:
            await sess.close()
            server.close(); await server.wait_closed()

    async def test_submit_before_login_is_refused(self):
        server, port = await self._stub()
        sess = UserSession(host="127.0.0.1", port=port, email="e@x.com",
                           password="pw", character="T", use_tls=False)
        # Not started → not connected.
        self.assertIn(sess.submit("look"), ("disconnected", "not_logged_in"))
        server.close(); await server.wait_closed()

    async def test_close_drops_credentials(self):
        server, port = await self._stub()
        sess = UserSession(host="127.0.0.1", port=port, email="e@x.com",
                           password="secret-pw", character="T", use_tls=False)
        await sess.start()
        await _wait(lambda: sess.submit("x") == "ok")
        await sess.close()
        self.assertIsNone(sess.password)
        self.assertIsNone(sess.email)
        self.assertIsNone(sess.character)
        self.assertFalse(sess.alive)
        server.close(); await server.wait_closed()


class SessionManagerTest(unittest.IsolatedAsyncioTestCase):
    async def _stub(self):
        room = Room()
        server = await asyncio.start_server(lambda r, w: handle(r, w, room), "127.0.0.1", 0)
        return server, server.sockets[0].getsockname()[1]

    async def test_create_resolve_and_isolation(self):
        server, port = await self._stub()
        mgr = SessionManager(host="127.0.0.1", port=port, use_tls=False)
        try:
            ta = await mgr.create_user_session("a@x.com", "pw-a", "Alice")
            tb = await mgr.create_user_session("b@x.com", "pw-b", "Bob")
            self.assertNotEqual(ta, tb)
            ha = mgr.resolve(ta); hb = mgr.resolve(tb)
            self.assertIsNotNone(ha); self.assertIsNotNone(hb)
            self.assertIsNot(ha.hub, hb.hub)          # isolated hubs
            self.assertIsNone(mgr.resolve("not-a-token"))  # unknown token → nil
            # token A resolves to A's session only (never B's).
            self.assertIs(mgr.resolve(ta).hub, ha.hub)
        finally:
            await mgr.close_all()
            server.close(); await server.wait_closed()

    async def test_unregister_closes_and_drops_creds(self):
        server, port = await self._stub()
        mgr = SessionManager(host="127.0.0.1", port=port, use_tls=False)
        try:
            t = await mgr.create_user_session("a@x.com", "secret-pw", "Alice")
            sess = mgr._sessions[t]        # internal handle's session, for assertion
            self.assertTrue(await mgr.unregister(t))
            self.assertIsNone(mgr.resolve(t))         # gone
            self.assertIsNone(sess.password)          # creds dropped
        finally:
            await mgr.close_all()
            server.close(); await server.wait_closed()

    async def test_bootstrap_is_protected_from_unregister(self):
        mgr = SessionManager(host="127.0.0.1", port=1, use_tls=False)
        mgr.register_bootstrap("static-tkn", hub=object(), submit=lambda t: "ok")
        self.assertIsNotNone(mgr.resolve("static-tkn"))
        self.assertFalse(await mgr.unregister("static-tkn"))   # cannot tear down Hero
        self.assertIsNotNone(mgr.resolve("static-tkn"))

    async def test_max_sessions_enforced(self):
        server, port = await self._stub()
        mgr = SessionManager(host="127.0.0.1", port=port, use_tls=False, max_user_sessions=1)
        try:
            await mgr.create_user_session("a@x.com", "pw", "A")
            with self.assertRaises(SessionLimitError):
                await mgr.create_user_session("b@x.com", "pw", "B")
        finally:
            await mgr.close_all()
            server.close(); await server.wait_closed()

    async def test_reap_idle_closes_stale_sessions(self):
        """A session whose last_active is older than idle_ttl is closed and its
        token is unregistered; its credentials are dropped."""
        server, port = await self._stub()
        mgr = SessionManager(host="127.0.0.1", port=port, use_tls=False, idle_ttl=10)
        try:
            t = await mgr.create_user_session("a@x.com", "secret-pw", "Alice")
            sess = mgr._sessions[t]          # grab before reaping removes it
            sess.last_active = 0             # far in the past
            await mgr.reap_idle(now=1000)
            self.assertIsNone(mgr.resolve(t))    # token gone
            self.assertIsNone(sess.password)     # credentials dropped
        finally:
            await mgr.close_all()
            server.close(); await server.wait_closed()

    async def test_reap_idle_keeps_active_sessions(self):
        """A session whose last_active is within idle_ttl is not reaped."""
        server, port = await self._stub()
        mgr = SessionManager(host="127.0.0.1", port=port, use_tls=False, idle_ttl=10)
        try:
            t = await mgr.create_user_session("a@x.com", "pw", "Alice")
            sess = mgr._sessions[t]
            sess.last_active = 995           # only 5 s old at now=1000 (< ttl=10)
            await mgr.reap_idle(now=1000)
            self.assertIsNotNone(mgr.resolve(t))   # still alive
        finally:
            await mgr.close_all()
            server.close(); await server.wait_closed()

    async def test_reap_idle_disabled_when_ttl_none(self):
        """When idle_ttl=None the reaper is disabled; no session is ever reaped."""
        server, port = await self._stub()
        mgr = SessionManager(host="127.0.0.1", port=port, use_tls=False, idle_ttl=None)
        try:
            t = await mgr.create_user_session("a@x.com", "pw", "Alice")
            sess = mgr._sessions[t]
            sess.last_active = 0             # would expire immediately if TTL were set
            await mgr.reap_idle(now=10 ** 9)
            self.assertIsNotNone(mgr.resolve(t))   # still alive
        finally:
            await mgr.close_all()
            server.close(); await server.wait_closed()


class _FakeRegistry:
    """Minimal stand-in: the reaper only needs reapable_ids(now)."""
    def __init__(self, ids=()):
        self.ids = set(ids)
    def reapable_ids(self, now):
        return set(self.ids)


class RevocationReaperTest(unittest.IsolatedAsyncioTestCase):
    """Session<->enrollment binding and the cross-process revocation reaper (#140)."""

    async def _stub(self):
        room = Room()
        server = await asyncio.start_server(lambda r, w: handle(r, w, room), "127.0.0.1", 0)
        return server, server.sockets[0].getsockname()[1]

    async def test_create_records_enrollment_binding(self):
        server, port = await self._stub()
        mgr = SessionManager(host="127.0.0.1", port=port, use_tls=False)
        try:
            t = await mgr.create_user_session("a@x.com", "pw", "A", enrollment_id="enr1")
            self.assertEqual(mgr._enrollments[t], "enr1")
        finally:
            await mgr.close_all()
            server.close(); await server.wait_closed()

    async def test_reap_revoked_tears_down_bound_session(self):
        server, port = await self._stub()
        reg = _FakeRegistry()
        mgr = SessionManager(host="127.0.0.1", port=port, use_tls=False, enroll_registry=reg)
        try:
            t = await mgr.create_user_session("a@x.com", "secret-pw", "A", enrollment_id="enr1")
            sess = mgr._sessions[t]
            reg.ids = {"enr1"}                 # credential is now revoked/expired
            await mgr.reap_revoked(now=1000.0)
            self.assertIsNone(mgr.resolve(t))  # session torn down
            self.assertIsNone(sess.password)   # credentials dropped
            self.assertNotIn(t, mgr._enrollments)
        finally:
            await mgr.close_all()
            server.close(); await server.wait_closed()

    async def test_reap_revoked_leaves_other_credentials(self):
        server, port = await self._stub()
        reg = _FakeRegistry()
        mgr = SessionManager(host="127.0.0.1", port=port, use_tls=False, enroll_registry=reg)
        try:
            ta = await mgr.create_user_session("a@x.com", "pw", "A", enrollment_id="enrA")
            tb = await mgr.create_user_session("b@x.com", "pw", "B", enrollment_id="enrB")
            reg.ids = {"enrA"}                 # only A revoked
            await mgr.reap_revoked(now=1000.0)
            self.assertIsNone(mgr.resolve(ta))     # A reaped
            self.assertIsNotNone(mgr.resolve(tb))  # B survives -- revocation is per-user
        finally:
            await mgr.close_all()
            server.close(); await server.wait_closed()

    async def test_reap_revoked_keeps_unbound_sessions(self):
        # A session minted with no enrollment id (open mode) is never revocation-reaped.
        server, port = await self._stub()
        reg = _FakeRegistry(ids={"enrX"})
        mgr = SessionManager(host="127.0.0.1", port=port, use_tls=False, enroll_registry=reg)
        try:
            t = await mgr.create_user_session("a@x.com", "pw", "A")   # enrollment_id=None
            await mgr.reap_revoked(now=1000.0)
            self.assertIsNotNone(mgr.resolve(t))
        finally:
            await mgr.close_all()
            server.close(); await server.wait_closed()

    async def test_reap_revoked_noop_without_registry(self):
        server, port = await self._stub()
        mgr = SessionManager(host="127.0.0.1", port=port, use_tls=False)  # no registry
        try:
            t = await mgr.create_user_session("a@x.com", "pw", "A", enrollment_id="enr1")
            await mgr.reap_revoked(now=1000.0)
            self.assertIsNotNone(mgr.resolve(t))
        finally:
            await mgr.close_all()
            server.close(); await server.wait_closed()

    async def test_bootstrap_never_bound_or_reaped(self):
        # The bootstrap session lives only in _handles, never _sessions/_enrollments,
        # so reap_revoked cannot touch it even if its (nonexistent) id were reapable.
        reg = _FakeRegistry(ids={"anything"})
        mgr = SessionManager(host="127.0.0.1", port=1, use_tls=False, enroll_registry=reg)
        mgr.register_bootstrap("static-tkn", hub=object(), submit=lambda t: "ok")
        self.assertNotIn("static-tkn", mgr._enrollments)
        await mgr.reap_revoked(now=1000.0)
        self.assertIsNotNone(mgr.resolve("static-tkn"))   # untouched

    async def test_run_reaper_survives_registry_errors(self):
        # A transient registry/DB error must not permanently kill the reaper (and thus
        # silently stop revocation enforcement). The loop should skip the bad cycle.
        class _BoomRegistry:
            def reapable_ids(self, now):
                raise RuntimeError("simulated transient sqlite error")
        mgr = SessionManager(host="127.0.0.1", port=1, use_tls=False,
                             enroll_registry=_BoomRegistry())
        task = asyncio.create_task(mgr.run_reaper(interval=0.01))
        await asyncio.sleep(0.06)          # several cycles, each raising
        self.assertFalse(task.done())      # reaper survived; still running
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    async def test_end_to_end_with_real_registry(self):
        # Prove the binding + reaper work against the real EnrollmentRegistry.
        import os
        import tempfile
        from glyph_relay.enrollment import EnrollmentRegistry
        d = tempfile.TemporaryDirectory(); self.addCleanup(d.cleanup)
        reg = EnrollmentRegistry(os.path.join(d.name, "e.db"), iters=1000)
        ident, _secret = reg.add("phone", now=1.0)
        server, port = await self._stub()
        mgr = SessionManager(host="127.0.0.1", port=port, use_tls=False, enroll_registry=reg)
        try:
            t = await mgr.create_user_session("a@x.com", "pw", "A", enrollment_id=ident)
            await mgr.reap_revoked(now=2.0)
            self.assertIsNotNone(mgr.resolve(t))      # active -> survives
            reg.revoke(ident, now=3.0)
            await mgr.reap_revoked(now=4.0)
            self.assertIsNone(mgr.resolve(t))         # revoked -> reaped
        finally:
            await mgr.close_all()
            server.close(); await server.wait_closed()
