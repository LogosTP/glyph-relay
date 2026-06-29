# SPDX-License-Identifier: Elastic-2.0
"""Coarse push-trigger classification + best-effort notify POST (spec §4.2.1).

The relay does NOT speak HTTP/2 and never matches per-user highlight keywords;
those live only in the private ``glyph-hosted`` store. Here the relay does a cheap,
synchronous classification of each ``Hub.publish`` event into a coarse ``category``
plus a bounded ``text`` snippet, applies a per-(tenant, session) sliding-window
outbound rate limit, and **fire-and-forgets** a plain HTTP/1.1 POST to the
co-located ``glyph-hosted`` sender (which holds the token registry + consent +
keywords and performs the APNs send).

Stdlib-only: ``urllib.request`` for the POST and ``loop.run_in_executor`` to keep
``Hub.publish`` (which runs on the asyncio loop in the MUD read path) non-blocking,
mirroring the existing pbkdf2 / DNS offload. The shared notify secret and the event
text are NEVER logged. Unset notify config ⇒ no ``PushNotifier`` is constructed, so
self-host and hosted-without-push are byte-for-byte unchanged.
"""
import asyncio
import json
import time
import urllib.request

from .relay import SlidingWindowRateLimiter


def _snippet(t):
    """Bounded snippet (≤256 chars) of ``t``; ``None`` when ``t`` is falsy."""
    if not t:
        return None
    return str(t)[:256]


def classify_event(kind, data):
    """Map one relay event to ``(category, text)``, or ``(None, None)`` to skip.

    Coarse classification only (spec §4.2.1 table) — no keyword matching, which is a
    private ``glyph-hosted`` concern. For ``highlight`` the relay forwards a bounded
    ``output`` line and the hosted side decides; ``combat``/``death`` have no clean
    relay signal and are out of the first go-live."""
    if kind == "status":
        if isinstance(data, dict) and data.get("state") == "disconnected":
            return ("disconnect", None)
        return (None, None)
    if kind == "structured":
        if isinstance(data, dict) and data.get("type") == "commChannel":
            inner = data.get("data") or {}
            ch = (inner.get("channel") or "").lower()
            cat = "tell" if "tell" in ch else "channel"
            return (cat, _snippet(inner.get("text")))
        return (None, None)
    if kind == "output":
        if isinstance(data, dict) and (data.get("text") or "").strip():
            return ("highlight", _snippet(data.get("text")))
        return (None, None)
    return (None, None)


def post_notify(url, secret, payload, *, timeout=5.0):
    """Best-effort server-to-server notify POST (spec §4.2.1 notify contract).

    Sends ``payload`` as JSON to ``url`` with ``Content-Type: application/json`` and
    the shared ``X-Relay-Notify: <secret>`` header. **Never raises** — a dead or
    refusing hosted sender must never break the relay's event delivery — and **never
    logs the secret or the payload text**."""
    try:
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url, data=body, method="POST",
            headers={"Content-Type": "application/json",
                     "X-Relay-Notify": secret})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp.read()
    except Exception:
        # Best-effort: swallow ALL exceptions (connection refused, timeout, HTTP
        # error, malformed payload). Deliberately no logging — never the secret or
        # the event text.
        pass


class PushNotifier:
    """Per-(tenant, session) rate-limited, fire-and-forget push notify dispatcher.

    Constructed only when ``RELAY_NOTIFY_URL`` + ``RELAY_NOTIFY_SECRET`` are both set
    (``config.build_relay``, hosted mode). ``__call__`` is invoked from
    ``Hub.publish`` on the asyncio loop in the MUD read path, so it MUST NOT block:
    it classifies synchronously, rate-limits, builds the payload, and hands the POST
    to ``dispatch`` (default: an off-loop executor). ``dispatch`` is injectable so
    tests capture payloads synchronously without real I/O."""

    def __init__(self, notify_url, notify_secret, *, classify=classify_event,
                 rate=120, window=60.0, dispatch=None, timeout=5.0):
        self._url = notify_url
        self._secret = notify_secret
        self._classify = classify
        self._rate = rate
        self._window = window
        self._timeout = timeout
        self._dispatch = dispatch if dispatch is not None else self._default_dispatch
        # One SlidingWindowRateLimiter per (tenant_id, session_key), created lazily.
        self._limiters = {}

    def __call__(self, tenant_id, session_key, event_id, kind, data):
        category, text = self._classify(kind, data)
        if category is None:
            return
        if self._rate > 0:
            key = (tenant_id, session_key)
            limiter = self._limiters.get(key)
            if limiter is None:
                limiter = SlidingWindowRateLimiter(self._rate, self._window)
                self._limiters[key] = limiter
            if not limiter.allow(time.monotonic()):
                # Shed under flood: highlight delivery is best-effort (spec §4.2.1).
                return
        payload = {
            "tenant_id": tenant_id,
            "session_key": session_key,
            "event_id": event_id,
            "kind": kind,
            "category": category,
            "text": text,
            "ts": time.time(),
        }
        self._dispatch(payload)

    def _default_dispatch(self, payload):
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return  # no running loop (nothing to offload onto) — drop best-effort
        fut = loop.run_in_executor(
            None, post_notify, self._url, self._secret, payload)
        # Retrieve any executor exception so it is not reported as "never retrieved"
        # (post_notify itself already swallows, so this is belt-and-suspenders).
        fut.add_done_callback(lambda f: f.exception())
