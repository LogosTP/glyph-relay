# glyph_relay/sessions.py
# SPDX-License-Identifier: Elastic-2.0
"""Per-user multi-session relay support: shared security helpers, a RAM-only
UserSession, and a SessionManager keyed by per-user bearer token.

The maintainer's always-on bootstrap session remains the App in app.py (registered
under the static token); these types add the per-user product sessions described in
the dual-mode spec §4. Credentials for a UserSession live in RAM only and are
dropped on teardown — there is no at-rest store for product users.
"""
import asyncio
import hmac
import secrets as _secrets_mod   # only used by SessionManager (Task 3)
import time                      # wall-clock for enrollment revocation/expiry (#140)

from ._scrub import scrub_secrets, drain_queue  # re-export for back-compat
from .connection import Connection
from .hub import Hub
from .negotiator import Negotiator
from .structured import structured_events
from .login import LoginFlow, default_login_steps, HEALTHY_SESSION_SECONDS


class UserSession:
    """One product user's RAM-only MUD session, driven solely by the relay."""

    def __init__(self, host, port, email, password, character, *,
                 use_tls=True, ca_file=None, ca_data=None, backlog=500,
                 term_width=120, term_height=40, reconnect=True,
                 connect_host=None, history=None, tenant_id=None, session_key=None,
                 push_notifier=None):
        self.host = host
        self.port = port
        self.email = email
        self.password = password
        self.character = character
        self.use_tls = use_tls
        self.ca_file = ca_file
        self.ca_data = ca_data
        # §2.2 DNS-rebind defense: when set, the socket connects to this pinned IP
        # while TLS SNI/cert verification still uses the original ``host``.
        self.connect_host = connect_host
        self.term_width = term_width
        self.term_height = term_height
        self.reconnect = reconnect
        # Per-tenant tag (§2.3) + durable history sink (§3). Self-host leaves both at
        # their defaults: tenant_id=None, history=None -> a RAM-only Hub, unchanged.
        self.tenant_id = tenant_id
        self.session_key = session_key
        self.created_at = None        # wall-clock epoch, set by the manager at mint
        self.hub = Hub(backlog, sink=history, tenant_id=tenant_id, session_key=session_key,
                       notifier=push_notifier)
        self._steps = default_login_steps(email, password, character)
        self._secrets = {s.value for s in self._steps if s.secret and s.value}
        self._login = LoginFlow(self._steps)
        self._connected = False
        self._conn = None
        self.outbound = None          # created in start() (loop-binding rule)
        self._task = None
        self.alive = False
        self.last_active = None

    async def start(self):
        self.outbound = asyncio.Queue()
        self.alive = True
        loop = asyncio.get_running_loop()
        self.last_active = loop.time()
        self._task = asyncio.create_task(self._supervise())

    def submit(self, text):
        if not self._connected:
            return "disconnected"
        if not self._login.password_sent:
            return "not_logged_in"
        self.outbound.put_nowait(("phone", text, text))
        loop = asyncio.get_running_loop()
        self.last_active = loop.time()
        return "ok"

    async def close(self):
        self.alive = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        if self._conn is not None:
            await self._conn.close()
            self._conn = None
        # Drop credentials from RAM.
        self.email = None
        self.password = None
        self.character = None
        self._steps = []
        self._login = None
        self._secrets = set()

    def _build_negotiator(self):
        return Negotiator(cols=self.term_width, rows=self.term_height)

    async def _supervise(self):
        backoff = 1
        loop = asyncio.get_running_loop()
        while True:
            conn = Connection(self.host, self.port, self.use_tls, False,
                              negotiator=self._build_negotiator(), cafile=self.ca_file,
                              cadata=self.ca_data, connect_host=self.connect_host)
            self._conn = conn
            connected_at = None
            try:
                await conn.connect()
                connected_at = loop.time()
                self._login = LoginFlow(self._steps)
                drain_queue(self.outbound)
                self._connected = True
                self.hub.publish("status", {"state": "connected"})
                await self._run(conn)
            except OSError:
                pass
            finally:
                if self._connected:
                    self._connected = False
                    self.hub.publish("status", {"state": "disconnected"})
            if not self.reconnect:
                return
            if connected_at is not None and (loop.time() - connected_at) >= HEALTHY_SESSION_SECONDS:
                backoff = 1
            self.hub.publish("status", {"state": "reconnecting"})
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 30)

    async def _run(self, conn):
        reader = asyncio.create_task(self._reader(conn))
        writer = asyncio.create_task(self._writer(conn))
        try:
            await asyncio.wait({reader, writer}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            reader.cancel(); writer.cancel()
            await conn.close()

    async def _reader(self, conn):
        async for text, events in conn.receive():
            prompt = any(kind == "prompt" for kind, _ in events)
            scrubbed = ""
            if text:
                scrubbed = scrub_secrets(self._secrets, text)
                for item in self._login.feed(text, events):
                    await self.outbound.put(item)
            if text or prompt:
                self.hub.publish("output", {"text": scrubbed, "prompt": prompt})
            # Forward out-of-band GMCP packages as shared structured events (#59).
            for structured in structured_events(events):
                self.hub.publish("structured", structured)

    async def _writer(self, conn):
        while True:
            source, cmd, display = await self.outbound.get()
            try:
                await conn.send(cmd)
            except OSError:
                return  # never re-queue onto a fresh login
            self.hub.publish("echo", {"source": source, "text": scrub_secrets(self._secrets, display)})


class SessionLimitError(Exception):
    """Raised when the relay is at its concurrent-user-session cap."""


class SessionHandle:
    def __init__(self, hub, submit, close=None, is_bootstrap=False):
        self.hub = hub
        self.submit = submit
        self.close = close
        self.is_bootstrap = is_bootstrap


class SessionManager:
    def __init__(self, *, host, port, use_tls=True, ca_file=None, max_user_sessions=20,
                 idle_ttl=None, enroll_registry=None, max_sessions_per_tenant=None,
                 history=None, push_notifier=None):
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.ca_file = ca_file
        self.max_user_sessions = max_user_sessions
        # Per-tenant cap (§2.3 noisy-neighbor): None = no per-tenant limit (self-host,
        # where the global cap is the only bound). Enforced alongside the global cap.
        self.max_sessions_per_tenant = max_sessions_per_tenant
        self.idle_ttl = idle_ttl          # seconds; None = idle reaper disabled
        # Enrollment registry (#140): None = no per-user revocation. When set, the
        # reaper tears down sessions whose minting enrollment id has been revoked/expired.
        self.enroll_registry = enroll_registry
        # Durable per-tenant history sink (§3). None = RAM-only Hubs (self-host).
        self.history = history
        # Push-trigger notifier (§4.2.1), threaded into each session's Hub. None =
        # feature off (self-host / hosted-without-push), unchanged.
        self.push_notifier = push_notifier
        self._bootstrap_token = None
        self._handles = {}            # token -> SessionHandle
        self._sessions = {}           # token -> UserSession (user sessions only)
        self._enrollments = {}        # token -> minting enrollment id (user sessions only)

    def register_bootstrap(self, token, hub, submit):
        if token is None:
            raise ValueError("bootstrap token must not be None")
        self._bootstrap_token = token
        self._handles[token] = SessionHandle(hub, submit, close=None, is_bootstrap=True)

    def resolve(self, token):
        if not isinstance(token, str):
            return None
        cand = token.encode("utf-8")
        for known, handle in self._handles.items():
            if hmac.compare_digest(cand, known.encode("utf-8")):
                return handle
        return None

    def count_user_sessions(self, tenant_id=None):
        """Live user-session count: global (``tenant_id=None``) or for one tenant."""
        if tenant_id is None:
            return len(self._sessions)
        return sum(1 for s in self._sessions.values()
                   if getattr(s, "tenant_id", None) == tenant_id)

    def tenant_for_token(self, token):
        """The owning tenant id for a bearer token, or ``None`` if it owns no live
        user session. Constant-time per entry (mirrors ``resolve``)."""
        if not isinstance(token, str):
            return None
        cand = token.encode("utf-8")
        for tok, sess in self._sessions.items():
            if hmac.compare_digest(cand, tok.encode("utf-8")):
                return getattr(sess, "tenant_id", None)
        return None

    def list_tenant_sessions(self, tenant_id):
        """The caller's own live sessions (§2.4) — tenant-scoped, never global, never
        the password. ``sessionKey`` is the bearer token; ``lastEventId`` is the Hub
        cursor for #141's re-attach."""
        out = []
        for token, sess in self._sessions.items():
            if getattr(sess, "tenant_id", None) != tenant_id:
                continue
            row = {
                "host": sess.host,
                "port": sess.port,
                "tls": bool(sess.use_tls),
                "email": sess.email,
                "sessionKey": token,
                "createdAt": sess.created_at,
                "lastEventId": sess.hub.last_event_id(),
            }
            if sess.character is not None:
                row["character"] = sess.character
            out.append(row)
        return out

    def session_for_token(self, token):
        """The live ``UserSession`` a bearer token owns, or ``None`` (constant-time)."""
        if not isinstance(token, str):
            return None
        cand = token.encode("utf-8")
        for tok, sess in self._sessions.items():
            if hmac.compare_digest(cand, tok.encode("utf-8")):
                return sess
        return None

    async def reap_idle(self, now):
        """Close and unregister user sessions that have been idle longer than
        ``idle_ttl`` seconds.  Takes ``now`` (a loop-time float) explicitly so
        the caller — or a unit test — controls the clock.  No-op when
        ``idle_ttl`` is None."""
        if self.idle_ttl is None:
            return
        for token in list(self._sessions):
            sess = self._sessions.get(token)   # re-fetch: a prior await may have removed it
            if sess is None:
                continue
            if sess.last_active is not None and (now - sess.last_active) > self.idle_ttl:
                await self.unregister(token)

    async def reap_revoked(self, now):
        """Close and unregister user sessions whose minting enrollment id has been
        revoked or expired.  ``now`` is a WALL-CLOCK epoch (the enrollment clock, not
        the loop clock used by idle reaping).  No-op without an enrollment registry.

        The bootstrap session has no enrollment binding (it lives only in ``_handles``,
        never ``_sessions``/``_enrollments``), so it is structurally exempt."""
        if self.enroll_registry is None:
            return
        reapable = self.enroll_registry.reapable_ids(now)
        if not reapable:
            return
        for token in list(self._sessions):
            if self._enrollments.get(token) in reapable:
                await self.unregister(token)

    async def run_reaper(self, interval=60):
        """Background loop that reaps idle sessions (loop clock) and sessions minted
        under a revoked/expired enrollment (wall clock) every ``interval`` seconds.
        Start via ``asyncio.create_task``; cancel to stop."""
        while True:
            await asyncio.sleep(interval)
            try:
                await self.reap_idle(asyncio.get_running_loop().time())
                await self.reap_revoked(time.time())
            except Exception:
                # A transient registry/DB error (e.g. sqlite3.OperationalError, which is
                # NOT an OSError) must not kill this long-lived security-enforcement loop
                # and silently stop revocation + idle reaping. Skip this cycle and retry
                # next tick. CancelledError is a BaseException, so a clean shutdown's
                # cancel still propagates and ends the loop here.
                pass

    async def create_user_session(self, email, password, character, *,
                                  tenant_id=None, target=None, connect_host=None,
                                  enrollment_id=None, now=None):
        """Mint a per-user session. ``email``/``password``/``character`` stay the
        first three positional args (self-host call sites unchanged). ``target`` is an
        optional ``{host, port, tls, ca?}`` per-server override (§2.1); ``connect_host``
        is the SSRF-pinned IP (§2.2); ``tenant_id`` tags the session for isolation +
        per-tenant quota; ``enrollment_id`` binds it for the #140 revocation reaper."""
        # Global cap then per-tenant cap, both BEFORE minting (§2.3).
        if self.count_user_sessions() >= self.max_user_sessions:
            raise SessionLimitError()
        if (self.max_sessions_per_tenant is not None and tenant_id is not None
                and self.count_user_sessions(tenant_id) >= self.max_sessions_per_tenant):
            raise SessionLimitError()
        host = self.host
        port = self.port
        use_tls = self.use_tls
        ca_data = None
        if target is not None:
            host = target["host"]
            port = int(target["port"])
            use_tls = bool(target["tls"])
            ca_data = target.get("ca")
        # sess.start() schedules via create_task and never suspends, so nothing
        # can interleave between the cap-check above and the register below — no TOCTOU.
        token = _secrets_mod.token_urlsafe(32)
        sess = UserSession(host=host, port=port, email=email,
                           password=password, character=character,
                           use_tls=use_tls, ca_file=self.ca_file, ca_data=ca_data,
                           connect_host=connect_host, history=self.history,
                           tenant_id=tenant_id, session_key=token,
                           push_notifier=self.push_notifier)
        sess.created_at = now if now is not None else time.time()
        await sess.start()
        self._sessions[token] = sess
        self._handles[token] = SessionHandle(sess.hub, sess.submit,
                                             close=sess.close, is_bootstrap=False)
        # Bind the session to the enrollment that minted it so the reaper can target it
        # on revocation. Open-mode sessions (no registry) pass None and stay unbound.
        if enrollment_id is not None:
            self._enrollments[token] = enrollment_id
        return token

    async def reap_tenant(self, tenant_id):
        """Close + unregister every live session owned by ``tenant_id`` (admin revoke,
        §3.5). Returns the number reaped. Bootstrap is exempt (never in ``_sessions``)."""
        victims = [tok for tok, s in self._sessions.items()
                   if getattr(s, "tenant_id", None) == tenant_id]
        for tok in victims:
            await self.unregister(tok)
        return len(victims)

    async def unregister(self, token):
        handle = self._handles.get(token)
        if handle is None or handle.is_bootstrap:
            return False
        self._handles.pop(token, None)
        self._enrollments.pop(token, None)
        sess = self._sessions.pop(token, None)
        if sess is not None:
            await sess.close()
        return True

    async def close_all(self):
        for token in list(self._sessions):
            await self.unregister(token)
