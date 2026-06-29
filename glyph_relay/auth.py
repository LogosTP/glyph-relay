# SPDX-License-Identifier: Elastic-2.0
"""Pluggable relay authentication.

Two implementations behind one ``authenticate(headers) -> tenant_id | None``
surface so ``relay.py`` is mode-agnostic:

- ``StaticEnrollAuth`` (self-host): an optional global shared secret in the
  ``X-Relay-Enroll`` header. ``secret is None`` means the endpoint is open.
- ``BrokerTokenAuth`` (hosted): an HMAC-signed broker token minted by the backend
  control plane, carried in the SAME ``X-Relay-Enroll`` header so the wire format
  and iOS app do not change between modes. The token is

      v1.<b64url(payload)>.<b64url(sig)>
      sig = HMAC-SHA256(SHARED_HMAC_KEY, "v1." + b64url(payload))
      payload = {"tid","exp","iat"}

  validated against a key map (current + previous, for rotation), an ``exp`` in
  the future, and a mutable denylist of revoked tenant ids.

Stdlib only; no secrets are logged here.
"""
import base64
import hashlib
import hmac
import json
import time


class Authenticator:
    """Return the caller's ``tenant_id`` for a request, or ``None`` to reject."""

    def authenticate(self, headers):
        raise NotImplementedError


class StaticEnrollAuth(Authenticator):
    """Self-host gate: a global shared secret (or open when ``secret is None``)."""

    def __init__(self, secret=None, tenant_id="self"):
        self.secret = secret
        self.tenant_id = tenant_id

    def authenticate(self, headers):
        if self.secret is None:
            return self.tenant_id  # open self-host (no gate)
        # The header was latin-1 decoded upstream; re-encode to bytes so a non-ASCII
        # value compares as a plain mismatch rather than raising in compare_digest.
        provided = headers.get("x-relay-enroll", "").encode("latin-1")
        if hmac.compare_digest(provided, self.secret.encode("utf-8")):
            return self.tenant_id
        return None


def _b64url_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def decode_broker_token(token, keys, now, denylist):
    """Validate a broker token. Return its ``tid`` on success, else ``None``.

    ``keys`` maps key-id (e.g. ``"v1"``) -> key bytes (current + previous, so a
    token signed under a just-rotated key still verifies). A token is accepted iff
    the signature matches the key named by its kid, ``exp`` is strictly in the
    future, and ``tid`` is not denylisted."""
    if not isinstance(token, str):
        return None
    try:
        kid, payload_b64, sig_b64 = token.split(".")
    except ValueError:
        return None
    key = keys.get(kid)
    if key is None:
        return None
    signing_input = (kid + "." + payload_b64).encode("utf-8")
    expected = hmac.new(key, signing_input, hashlib.sha256).digest()
    try:
        got = _b64url_decode(sig_b64)
    except (ValueError, base64.binascii.Error):
        return None
    if not hmac.compare_digest(expected, got):
        return None
    try:
        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
        tid = payload["tid"]
        exp = int(payload["exp"])
    except (ValueError, KeyError, TypeError, base64.binascii.Error):
        return None
    if not isinstance(tid, str) or exp <= now or tid in denylist:
        return None
    return tid


class BrokerTokenAuth(Authenticator):
    """Hosted gate: HMAC broker-token verification (signature + expiry + denylist)."""

    def __init__(self, keys, denylist, clock=time.time):
        self.keys = keys            # {kid: key_bytes}, current + previous
        self.denylist = denylist    # mutable set of revoked tenant ids
        self.clock = clock

    def authenticate(self, headers):
        token = headers.get("x-relay-enroll", "")
        return decode_broker_token(token, self.keys, int(self.clock()), self.denylist)
