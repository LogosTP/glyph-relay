# SPDX-License-Identifier: Elastic-2.0
"""Localhost SSE-down + POST-up relay: phone clients attach to the live session.

Pure HTTP helpers (request parsing, bearer check) plus an asyncio server that
bridges a Hub (output) and a command-submit callback (input). Binds 127.0.0.1
only; a tunnel provides TLS + public reach.
"""
import asyncio
import hmac
import json
import time
from collections import deque

from .hub import format_sse_event


def parse_http_request(raw):
    """Parse an HTTP request head. Returns (method, path, headers) or None."""
    try:
        text = raw.decode("latin-1")
    except UnicodeDecodeError:
        return None
    lines = text.split("\r\n")
    parts = lines[0].split(" ") if lines else []
    if len(parts) < 2:
        return None
    method, path = parts[0], parts[1]
    headers = {}
    for line in lines[1:]:
        if not line:
            break
        name, sep, value = line.partition(":")
        if sep:
            headers[name.strip().lower()] = value.strip()
    return method, path, headers


def check_bearer(headers, token):
    auth = headers.get("authorization", "")
    prefix = "Bearer "
    if not auth.startswith(prefix):
        return False
    # Compare bytes, not str: the header was decoded latin-1 (parse_http_request),
    # so a non-ASCII byte yields a non-ASCII str that hmac.compare_digest refuses
    # (TypeError). Re-encoding the header value to its original bytes (latin-1) and
    # the token to UTF-8 keeps the compare constant-time and makes a bad token an
    # ordinary mismatch instead of a crash on the auth path.
    candidate = auth[len(prefix):].encode("latin-1")
    return hmac.compare_digest(candidate, token.encode("utf-8"))


def _bearer(headers):
    """Extract the raw bearer token string from the Authorization header (or '')."""
    auth = headers.get("authorization", "")
    prefix = "Bearer "
    if auth.startswith(prefix):
        return auth[len(prefix):]
    return ""


_REASONS = {200: "OK", 202: "Accepted", 400: "Bad Request",
            401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
            409: "Conflict", 413: "Payload Too Large", 429: "Too Many Requests",
            503: "Service Unavailable"}


class SlidingWindowRateLimiter:
    """Allow at most ``limit`` events per ``window`` seconds (sliding window).

    Pure and clock-injected: the caller passes ``now`` (a monotonic float such as
    ``loop.time()``), so tests control time exactly. A DENIED call records nothing,
    so a sustained flood cannot keep pushing the window forward — the limiter
    recovers once the recorded events age out."""

    def __init__(self, limit, window):
        self.limit = limit
        self.window = window
        self._events = deque()

    def allow(self, now):
        events = self._events
        cutoff = now - self.window
        while events and events[0] <= cutoff:
            events.popleft()
        if len(events) >= self.limit:
            return False
        events.append(now)
        return True


class Relay:
    # Ingest (§3.2): the closed kind-allowlist for device-supplied history. Never
    # 'status'/'structured' — a device cannot spoof authoritative live state.
    INGEST_KINDS = ("output", "echo")

    def __init__(self, hub=None, submit=None, token=None, manager=None,
                 host="127.0.0.1", port=8765, keepalive=15.0, read_timeout=30.0,
                 enroll_registry=None, session_rate=None, session_window=60.0,
                 authenticator=None, admin_secret=None, denylist=None, history=None,
                 target_allowlist=None, target_ports=None,
                 max_ingest_events=500, max_ingest_bytes=262144):
        if manager is None:
            # Legacy single-session shim: build a one-entry manager from the
            # positional hub/submit/token arguments.  Import lazily to avoid a
            # circular-import cycle (app.py → relay.py → sessions.py → app.py).
            from .sessions import SessionManager
            manager = SessionManager(host="-", port=0)
            manager.register_bootstrap(token, hub, submit)
        self.manager = manager
        self.host = host
        self.port = port
        self.keepalive = keepalive
        # Bound how long a request head/body may dawdle, so a client that opens a
        # connection and never finishes the request can't tie one up indefinitely
        # (slowloris) -- relevant once the tunnel is the public ingress.
        self.read_timeout = read_timeout
        # POST /session governance. Defaults are no-ops, so a direct Relay(...) and
        # the legacy single-session shim are unchanged; build_config supplies the
        # deployed defaults (rate limit on, enrollment registry off).
        #   - enroll_registry: if set (#140), POST /session requires a valid
        #     X-Relay-Enroll "id.secret" credential; None leaves the endpoint open.
        #   - session_limiter: caps the rate of session creation (None = unlimited).
        self.enroll_registry = enroll_registry
        self.session_limiter = (SlidingWindowRateLimiter(session_rate, session_window)
                                if session_rate else None)
        # Multi-tenant additions (hosted mode; all None/off in self-host):
        #   - authenticator: an auth.Authenticator that maps a request to a tenant id.
        #     When set it takes precedence over enroll_registry (broker-token / static).
        #   - admin_secret/denylist/history: the X-Relay-Admin revoke/purge surface.
        #   - target_allowlist/target_ports: SSRF policy for the per-server target.
        self.authenticator = authenticator
        self.admin_secret = admin_secret
        self.denylist = denylist
        self.history = history
        self.target_allowlist = target_allowlist
        self.target_ports = target_ports
        self.max_ingest_events = max_ingest_events
        self.max_ingest_bytes = max_ingest_bytes
        self._server = None

    async def start(self):
        self._server = await asyncio.start_server(self._handle, self.host, self.port)
        self.port = self._server.sockets[0].getsockname()[1]

    async def close(self):
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def _handle(self, reader, writer):
        try:
            head = await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"), self.read_timeout)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, OSError,
                asyncio.TimeoutError):
            writer.close()
            return
        parsed = parse_http_request(head)
        if parsed is None:
            await self._respond(writer, 400, {"error": "bad_request"})
            return
        method, path, headers = parsed
        route = path.split("?", 1)[0]

        # Open routes (no authentication required).
        if method == "GET" and route == "/health":
            await self._respond(writer, 200, {"ok": True})
            return
        if method == "POST" and route == "/session":
            await self._serve_create_session(reader, writer, headers)
            return

        # Admin routes (X-Relay-Admin secret; disabled in self-host where it is None).
        if method == "POST" and route in ("/admin/revoke", "/admin/purge"):
            await self._serve_admin(reader, writer, headers, route)
            return

        # Tenant-scoped routes: authed by bearer OR enrollment/broker for the tenant.
        if method == "GET" and route == "/sessions":
            await self._serve_list_sessions(writer, headers)
            return
        if (method == "POST" and route.startswith("/sessions/")
                and route.endswith("/ingest")):
            session_key = route[len("/sessions/"):-len("/ingest")]
            await self._serve_ingest(reader, writer, headers, session_key)
            return

        # All remaining routes require a valid bearer token.
        token = _bearer(headers)
        handle = self.manager.resolve(token)
        if handle is None:
            await self._respond(writer, 401, {"error": "unauthorized"})
            return

        if method == "GET" and route == "/events":
            await self._serve_events(writer, headers, handle.hub)
            return
        if method == "POST" and route == "/command":
            await self._serve_command(reader, writer, headers, handle.submit)
            return
        if method == "POST" and route == "/logout":
            if handle.is_bootstrap:
                await self._respond(writer, 403, {"error": "forbidden"})
                return
            await self.manager.unregister(token)
            await self._respond(writer, 200, {"status": "ok"})
            return

        await self._respond(writer, 404, {"error": "not_found"})

    async def _respond(self, writer, status, body):
        payload = json.dumps(body).encode("utf-8")
        head = ("HTTP/1.1 {} {}\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: {}\r\n"
                "Connection: close\r\n\r\n").format(
                    status, _REASONS.get(status, "OK"), len(payload))
        try:
            writer.write(head.encode("latin-1") + payload)
            await writer.drain()
        except OSError:
            pass
        finally:
            writer.close()

    async def _enroll_verify(self, headers):
        """Per-user enrollment check (#140). Return the minting enrollment id on
        success, or None. The X-Relay-Enroll header carries "id.secret"; the secret is
        verified against the registry's PBKDF2 hash.

        The pbkdf2 (tens of ms) runs in a thread executor so a POST /session never
        stalls live SSE/command delivery, and so unknown/revoked/expired/wrong-secret
        stay timing-indistinguishable (the registry pays one pbkdf2 either way)."""
        raw = headers.get("x-relay-enroll", "")
        ident, _, secret = raw.partition(".")
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, self.enroll_registry.verify, ident, secret, time.time())

    async def _read_body(self, reader, headers):
        """Read the request body (bounded by Content-Length + read_timeout). Returns
        the raw bytes, or b"" on a missing/negative/oversized/short read."""
        try:
            length = int(headers.get("content-length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > self.max_ingest_bytes:
            # A negative/absent length yields no body; an over-cap length is refused
            # here so an oversized ingest never buffers into memory.
            return b""
        try:
            return await asyncio.wait_for(reader.readexactly(length), self.read_timeout)
        except (asyncio.IncompleteReadError, OSError, asyncio.TimeoutError):
            return b""

    @staticmethod
    def _parse_target(data):
        """Validate an optional ``target`` from a /session body.

        Returns ``(target_or_None, ok)``: ``ok`` is False only when ``target`` is
        present but malformed (missing/typed-wrong host/port/tls) -> the caller 400s."""
        target = data.get("target")
        if target is None:
            return None, True
        try:
            host = target["host"]
            port = target["port"]
            tls = target["tls"]
        except (KeyError, TypeError):
            return None, False
        if not (isinstance(host, str) and host and isinstance(port, int)
                and not isinstance(port, bool) and isinstance(tls, bool)):
            return None, False
        out = {"host": host, "port": port, "tls": tls}
        ca = target.get("ca")
        if ca is not None:
            if not isinstance(ca, str):
                return None, False
            out["ca"] = ca
        return out, True

    async def _serve_create_session(self, reader, writer, headers):
        """Handle POST /session — never log body or minted token. Ordering per spec
        §2.1: body-400 -> auth-403 -> forbidden_target-403 -> rate-429 -> cap-503."""
        body = await self._read_body(reader, headers)
        try:
            data = json.loads(body.decode("utf-8")) if body else {}
            if not isinstance(data, dict):
                raise ValueError
            email = data["email"]
            password = data["password"]
            character = data["character"]
            if not (isinstance(email, str) and isinstance(password, str)
                    and isinstance(character, str)):
                raise ValueError
        except (ValueError, KeyError, TypeError, UnicodeDecodeError):
            await self._respond(writer, 400, {"error": "bad_request"})
            return
        # Target SHAPE validation is part of the body-400 phase (no I/O yet).
        target, ok = self._parse_target(data)
        if not ok:
            await self._respond(writer, 400, {"error": "bad_request"})
            return
        # Auth gate, checked AFTER the body is fully read so a rejected credential
        # returns a clean 403 instead of RST-ing an undrained body over the tunnel.
        # Still before the rate limit, so unauthorized callers never consume budget.
        # tenant_id tags the session for isolation/quota; enrollment_id binds it to a
        # #140 credential for the revocation reaper (self-host only).
        tenant_id, enrollment_id, authed = await self._authenticate_create(headers)
        if not authed:
            await self._respond(writer, 403, {"error": "forbidden"})
            return
        # Per-server target SSRF guard (§2.2): resolve ONCE, pin the IP, connect to it.
        # Runs only for authenticated callers (no unauthenticated SSRF probing).
        connect_host = None
        if target is not None:
            from .targets import is_allowed_target
            loop = asyncio.get_running_loop()
            pinned = await loop.run_in_executor(
                None, lambda: is_allowed_target(
                    target["host"], target["port"],
                    allowlist=self.target_allowlist, ports=self.target_ports))
            if pinned is None:
                await self._respond(writer, 403, {"error": "forbidden_target"})
                return
            connect_host = pinned
        # Rate-limit after validation+auth (a 400/403 must not cost budget) and before
        # opening a MUD socket. Counts attempts, so a flood is bounded below the cap.
        if self.session_limiter is not None and \
                not self.session_limiter.allow(asyncio.get_running_loop().time()):
            await self._respond(writer, 429, {"error": "rate_limited"})
            return
        # Import lazily (same cycle-prevention reason as __init__).
        from .sessions import SessionLimitError
        try:
            token = await self.manager.create_user_session(
                email, password, character, tenant_id=tenant_id, target=target,
                connect_host=connect_host, enrollment_id=enrollment_id)
        except SessionLimitError:
            await self._respond(writer, 503, {"error": "session_limit"})
            return
        # Respond with the token only — never echo back the credentials.
        await self._respond(writer, 200, {"token": token})

    async def _authenticate_create(self, headers):
        """Resolve a POST /session caller to ``(tenant_id, enrollment_id, authed)``.

        Precedence: an injected ``authenticator`` (hosted broker / static) wins; else
        the #140 ``enroll_registry`` (tenant == enrollment id); else the endpoint is
        open (tenant ``"self"``, unbound). ``authed`` is False only on a present-but-
        rejected credential."""
        if self.authenticator is not None:
            tenant_id = self.authenticator.authenticate(headers)
            return tenant_id, None, tenant_id is not None
        if self.enroll_registry is not None:
            enrollment_id = await self._enroll_verify(headers)
            return enrollment_id, enrollment_id, enrollment_id is not None
        return "self", None, True

    async def _serve_command(self, reader, writer, headers, submit):
        try:
            length = int(headers.get("content-length", "0"))
        except ValueError:
            length = 0
        body = b""
        if length > 0:  # guard: a negative Content-Length must not reach readexactly
            try:
                body = await asyncio.wait_for(
                    reader.readexactly(length), self.read_timeout)
            except (asyncio.IncompleteReadError, OSError, asyncio.TimeoutError):
                body = b""
        try:
            data = json.loads(body.decode("utf-8")) if body else {}
            if not isinstance(data, dict):  # non-object JSON (5, [..], "x") is invalid
                raise ValueError
            text = data["text"]
            if not isinstance(text, str):
                raise ValueError
        except (ValueError, KeyError, TypeError, UnicodeDecodeError):
            await self._respond(writer, 400, {"error": "bad_request"})
            return
        verdict = submit(text)
        if verdict == "ok":
            await self._respond(writer, 202, {"status": "accepted"})
        else:
            await self._respond(writer, 409, {"error": verdict})

    async def _serve_events(self, writer, headers, hub):
        since_id = None
        raw_since = headers.get("last-event-id")
        if raw_since is not None:
            try:
                since_id = int(raw_since)
            except ValueError:
                since_id = None
        head = ("HTTP/1.1 200 OK\r\n"
                "Content-Type: text/event-stream\r\n"
                "Cache-Control: no-cache\r\n"
                "Connection: keep-alive\r\n\r\n")
        try:
            writer.write(head.encode("latin-1"))
            await writer.drain()
        except OSError:
            writer.close()
            return
        q = hub.subscribe()
        # The dedup floor must rise only from what we actually replayed from the
        # backlog -- NOT from the client's Last-Event-ID. Seeding it from client
        # input blacks out all live events after a daemon restart (the fresh Hub's
        # ids start at 1, far below a stale client id), since every new id would
        # test <= the floor. Live events always carry ids strictly greater than
        # any backlog id, so a 0 floor still suppresses the one possible duplicate.
        last_id = 0
        # Send the current connection status first, so a (re)attaching client knows
        # the live state immediately even if its Last-Event-ID skipped past the
        # status event -- otherwise a phone-side reconnect leaves input disabled.
        emitted_status_id = None
        status_event = hub.latest_status()
        if status_event is not None:
            sid, skind, sdata = status_event
            writer.write(format_sse_event(sid, skind, sdata).encode("utf-8"))
            emitted_status_id = sid
        try:
            # durable_backlog reads the full SQLite history when a sink is wired
            # (hosted: catch-up can exceed the ~500-event RAM ring), else the RAM ring
            # (self-host, unchanged).
            for event_id, kind, data in hub.durable_backlog(since_id):
                if event_id == emitted_status_id:
                    continue  # already sent as the leading status snapshot
                writer.write(format_sse_event(event_id, kind, data).encode("utf-8"))
                last_id = event_id
            await writer.drain()
            while True:
                try:
                    event_id, kind, data = await asyncio.wait_for(
                        q.get(), self.keepalive)
                except asyncio.TimeoutError:
                    writer.write(b": keepalive\n\n")
                    await writer.drain()
                    continue
                if event_id <= last_id:
                    continue  # already replayed from backlog
                last_id = event_id
                writer.write(format_sse_event(event_id, kind, data).encode("utf-8"))
                await writer.drain()
        except (OSError, asyncio.CancelledError):
            pass
        finally:
            hub.unsubscribe(q)
            writer.close()

    # --- multi-tenant routes (§2.4 / §3.2 / §3.5) ------------------------------

    async def _resolve_tenant(self, headers):
        """The caller's tenant id for a tenant-scoped route, or ``None``.

        Accepts a bearer token of one of the caller's own sessions, OR an
        enrollment/broker credential in ``X-Relay-Enroll`` (§2.4). Never global."""
        token = _bearer(headers)
        tenant = self.manager.tenant_for_token(token)
        if tenant is not None:
            return tenant
        if self.authenticator is not None:
            return self.authenticator.authenticate(headers)
        if self.enroll_registry is not None:
            return await self._enroll_verify(headers)
        return None

    async def _serve_list_sessions(self, writer, headers):
        """GET /sessions — the caller's OWN live sessions only (§2.4), never the
        password, never another tenant's rows."""
        tenant = await self._resolve_tenant(headers)
        if tenant is None:
            await self._respond(writer, 401, {"error": "unauthorized"})
            return
        await self._respond(writer, 200,
                            {"sessions": self.manager.list_tenant_sessions(tenant)})

    async def _serve_ingest(self, reader, writer, headers, session_key):
        """POST /sessions/{sessionKey}/ingest — slot a device-supplied history window
        into the monotonic stream (§3.2). Tenant-authed + owned-session-only. The relay
        assigns its OWN ids (> after); clientSeq is advisory; kind is allowlisted."""
        tenant = await self._resolve_tenant(headers)
        if tenant is None:
            await self._respond(writer, 401, {"error": "unauthorized"})
            return
        sess = self.manager.session_for_token(session_key)
        if sess is None:
            await self._respond(writer, 404, {"error": "not_found"})
            return
        if getattr(sess, "tenant_id", None) != tenant:
            # Tenant mismatch: do not reveal existence beyond a flat 403.
            await self._respond(writer, 403, {"error": "forbidden"})
            return
        # Enforce the body-size cap up front (a too-long Content-Length reads as b"").
        try:
            length = int(headers.get("content-length", "0"))
        except ValueError:
            length = 0
        if length > self.max_ingest_bytes:
            await self._respond(writer, 413, {"error": "too_large"})
            return
        body = await self._read_body(reader, headers)
        try:
            data = json.loads(body.decode("utf-8")) if body else {}
            if not isinstance(data, dict):
                raise ValueError
            events = data["events"]
            if not isinstance(events, list):
                raise ValueError
        except (ValueError, KeyError, TypeError, UnicodeDecodeError):
            await self._respond(writer, 400, {"error": "bad_request"})
            return
        if len(events) > self.max_ingest_events:
            await self._respond(writer, 413, {"error": "too_large"})
            return
        accepted = 0
        for ev in events:
            if not isinstance(ev, dict):
                await self._respond(writer, 400, {"error": "bad_request"})
                return
            kind = ev.get("kind")
            payload = ev.get("data")
            # Closed kind-allowlist: a device cannot inject 'status'/'structured' and
            # spoof authoritative live state.
            if kind not in self.INGEST_KINDS:
                await self._respond(writer, 400, {"error": "bad_kind"})
                return
            # The relay is the ordering authority: publish() assigns the next monotonic
            # id (> every existing id, hence > after) and write-throughs to history +
            # live subscribers. The device's clientSeq is advisory and never used as id.
            sess.hub.publish(kind, payload)
            accepted += 1
        await self._respond(writer, 200,
                            {"accepted": accepted, "lastEventId": sess.hub.last_event_id()})

    def _admin_ok(self, headers):
        """Constant-time X-Relay-Admin check. False when admin is disabled (self-host:
        ``admin_secret`` is None) so the admin surface is simply absent there."""
        if self.admin_secret is None:
            return False
        provided = headers.get("x-relay-admin", "").encode("latin-1")
        return hmac.compare_digest(provided, self.admin_secret.encode("utf-8"))

    async def _serve_admin(self, reader, writer, headers, route):
        """POST /admin/revoke|purge — X-Relay-Admin-gated (§3.5). revoke denylists the
        tenant + reaps its live sessions; purge deletes its durable history."""
        if not self._admin_ok(headers):
            await self._respond(writer, 401, {"error": "unauthorized"})
            return
        body = await self._read_body(reader, headers)
        try:
            data = json.loads(body.decode("utf-8")) if body else {}
            tid = data.get("tenant_id") if isinstance(data, dict) else None
        except (ValueError, UnicodeDecodeError):
            tid = None
        if not isinstance(tid, str) or not tid:
            await self._respond(writer, 400, {"error": "bad_request"})
            return
        if route == "/admin/revoke":
            if self.denylist is not None:
                self.denylist.add(tid)        # future broker tokens for tid are rejected
            reaped = await self.manager.reap_tenant(tid)   # tear down live sessions now
            await self._respond(writer, 200, {"status": "ok", "reaped": reaped})
        else:  # /admin/purge
            deleted = self.history.delete(tid) if self.history is not None else 0
            await self._respond(writer, 200, {"status": "ok", "deleted": deleted})
