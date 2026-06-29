# SPDX-License-Identifier: Elastic-2.0
"""Pluggable relay authentication: StaticEnrollAuth (self-host) and BrokerTokenAuth
(hosted HMAC broker token). authenticate(headers) -> tenant_id | None."""
import base64
import hashlib
import hmac as _hmac
import json
import unittest

from glyph_relay.auth import (
    StaticEnrollAuth, BrokerTokenAuth, decode_broker_token,
)


class StaticEnrollAuthTests(unittest.TestCase):
    def test_no_secret_allows_open_selfhost(self):
        a = StaticEnrollAuth(secret=None)
        self.assertEqual(a.authenticate({}), "self")

    def test_matching_secret_returns_tenant(self):
        a = StaticEnrollAuth(secret="s3cret")
        self.assertEqual(a.authenticate({"x-relay-enroll": "s3cret"}), "self")

    def test_wrong_secret_rejected(self):
        a = StaticEnrollAuth(secret="s3cret")
        self.assertIsNone(a.authenticate({"x-relay-enroll": "nope"}))

    def test_missing_header_rejected_when_secret_set(self):
        self.assertIsNone(StaticEnrollAuth(secret="s3cret").authenticate({}))

    def test_non_ascii_header_is_mismatch_not_crash(self):
        # The header is latin-1 decoded; a non-ASCII byte must compare as a plain
        # mismatch, never raise.
        self.assertIsNone(StaticEnrollAuth(secret="s3cret").authenticate(
            {"x-relay-enroll": "caf\xe9"}))

    def test_custom_tenant_id(self):
        a = StaticEnrollAuth(secret=None, tenant_id="t-42")
        self.assertEqual(a.authenticate({}), "t-42")


def _make_token(key, payload, kid="v1"):
    raw = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode()).rstrip(b"=").decode()
    signing_input = kid + "." + raw
    sig = _hmac.new(key, signing_input.encode(), hashlib.sha256).digest()
    sig_b = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    return signing_input + "." + sig_b


class BrokerTokenAuthTests(unittest.TestCase):
    KEY = b"test-shared-key"

    def setUp(self):
        self.keys = {"v1": self.KEY}

    def test_valid_token_returns_tid(self):
        tok = _make_token(self.KEY, {"tid": "t-1", "exp": 9999999999, "iat": 1})
        self.assertEqual(
            decode_broker_token(tok, self.keys, now=1000, denylist=set()), "t-1")

    def test_expired_token_rejected(self):
        tok = _make_token(self.KEY, {"tid": "t-1", "exp": 500, "iat": 1})
        self.assertIsNone(
            decode_broker_token(tok, self.keys, now=1000, denylist=set()))

    def test_denylisted_tenant_rejected(self):
        tok = _make_token(self.KEY, {"tid": "t-1", "exp": 9999999999, "iat": 1})
        self.assertIsNone(
            decode_broker_token(tok, self.keys, now=1000, denylist={"t-1"}))

    def test_tampered_signature_rejected(self):
        tok = _make_token(self.KEY, {"tid": "t-1", "exp": 9999999999, "iat": 1})[:-2] + "xy"
        self.assertIsNone(
            decode_broker_token(tok, self.keys, now=1000, denylist=set()))

    def test_unknown_key_id_rejected(self):
        tok = _make_token(self.KEY, {"tid": "t-1", "exp": 9999999999, "iat": 1}, kid="v9")
        self.assertIsNone(
            decode_broker_token(tok, self.keys, now=1000, denylist=set()))

    def test_previous_key_accepted_for_rotation(self):
        tok = _make_token(self.KEY, {"tid": "t-1", "exp": 9999999999, "iat": 1})
        self.assertEqual(
            decode_broker_token(tok, {"v2": b"new", "v1": self.KEY},
                                now=1000, denylist=set()), "t-1")

    def test_garbage_token_rejected(self):
        for bad in ("", "no-dots", "a.b", None, "v1.notb64.notb64"):
            self.assertIsNone(
                decode_broker_token(bad, self.keys, now=1000, denylist=set()))

    def test_authenticator_reads_header(self):
        tok = _make_token(self.KEY, {"tid": "t-9", "exp": 9999999999, "iat": 1})
        a = BrokerTokenAuth(self.keys, denylist=set(), clock=lambda: 1000)
        self.assertEqual(a.authenticate({"x-relay-enroll": tok}), "t-9")

    def test_authenticator_denylist_is_live(self):
        # The denylist is the same mutable set the admin endpoint mutates; a tenant
        # added after construction is rejected on the next call.
        tok = _make_token(self.KEY, {"tid": "t-9", "exp": 9999999999, "iat": 1})
        denylist = set()
        a = BrokerTokenAuth(self.keys, denylist=denylist, clock=lambda: 1000)
        self.assertEqual(a.authenticate({"x-relay-enroll": tok}), "t-9")
        denylist.add("t-9")
        self.assertIsNone(a.authenticate({"x-relay-enroll": tok}))


class BrokerTokenSharedVectorTests(unittest.TestCase):
    """The broker-token seam must be byte-identical with the backend (#2 / glyph-hosted).

    Shared vector: key b"test-shared-key", payload {"tid":"t-1","exp":9999999999,"iat":1}
    built in that order with separators=(",",":"), no sort_keys. Both repos assert this
    exact token string, so a drift in either encoder is caught here."""

    KEY = b"test-shared-key"
    PAYLOAD = {"tid": "t-1", "exp": 9999999999, "iat": 1}
    # Fixed token string both repos pin (computed from the construction rule above).
    EXPECTED = ("v1.eyJ0aWQiOiJ0LTEiLCJleHAiOjk5OTk5OTk5OTksImlhdCI6MX0."
                "4lUH9B69mEQXcq6cogGISZKPQ_f7Sly8bDyb4Oo6-y4")

    def test_shared_vector_token_string_is_stable(self):
        self.assertEqual(_make_token(self.KEY, self.PAYLOAD), self.EXPECTED)

    def test_shared_vector_decodes_to_tid(self):
        self.assertEqual(
            decode_broker_token(self.EXPECTED, {"v1": self.KEY},
                                now=1, denylist=set()), "t-1")


if __name__ == "__main__":
    unittest.main()
