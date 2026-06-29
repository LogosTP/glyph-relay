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
            409: "Conflict", 429: "Too Many Requests", 503: "Service Unavailable"}


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
    def __init__(self, hub=None, submit=None, token=None, manager=None,
                 host="127.0.0.1", port=8765, keepalive=15.0, read_timeout=30.0,
                 enroll_registry=None, session_rate=None, session_window=60.0):
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

    async def _serve_create_session(self, reader, writer, headers):
        """Handle POST /session — open route, never log body or minted token."""
        try:
            length = int(headers.get("content-length", "0"))
        except ValueError:
            length = 0
        body = b""
        if length > 0:
            try:
                body = await asyncio.wait_for(
                    reader.readexactly(length), self.read_timeout)
            except (asyncio.IncompleteReadError, OSError, asyncio.TimeoutError):
                body = b""
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
        # Enrollment gate (#140), checked AFTER the body is fully read so a rejected
        # credential returns a clean 403 instead of RST-ing the connection with an
        # undrained body over the tunnel (which the app would see as a network error,
        # not .forbidden). Still before the rate limit, so unauthorized callers never
        # consume the create budget. enrollment_id binds the session to its credential
        # so the reaper can tear it down on revocation; None when the endpoint is open.
        enrollment_id = None
        if self.enroll_registry is not None:
            enrollment_id = await self._enroll_verify(headers)
            if enrollment_id is None:
                await self._respond(writer, 403, {"error": "forbidden"})
                return
        # Rate-limit session creation: after the body validates (a 400 must not cost
        # budget) and before we open a MUD socket. Counts attempts, so a flood is
        # bounded even below the concurrent-session cap.
        if self.session_limiter is not None and \
                not self.session_limiter.allow(asyncio.get_running_loop().time()):
            await self._respond(writer, 429, {"error": "rate_limited"})
            return
        # Import lazily (same cycle-prevention reason as __init__).
        from .sessions import SessionLimitError
        try:
            token = await self.manager.create_user_session(
                email, password, character, enrollment_id=enrollment_id)
        except SessionLimitError:
            await self._respond(writer, 503, {"error": "session_limit"})
            return
        # Respond with the token only — never echo back the credentials.
        await self._respond(writer, 200, {"token": token})

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
            for event_id, kind, data in hub.backlog(since_id):
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
