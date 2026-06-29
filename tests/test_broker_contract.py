# SPDX-License-Identifier: Elastic-2.0
"""Cross-repo broker-token byte-format contract (pins the wire vector).

The broker token is minted by the private ``glyph-hosted`` control plane and
verified here by ``glyph_relay.auth.decode_broker_token``. The two repos share a
byte format but NOT a codebase, so a silent drift in either side's encoder/decoder
would only surface in production. This test pins the exact byte format with a
SHARED TEST VECTOR (the same constants are asserted on the hosted side):

    key     = b"test-shared-key"
    payload = {"tid": "t-1", "exp": 9999999999, "iat": 1}   # built in key order
    token   = "v1." + b64url(json.dumps(payload, separators=(",", ":")))
                    + "." + b64url(HMAC_SHA256(key, "v1." + b64url(payload)))

The literal ``EXPECTED_TOKEN`` below is the canonical string. We assert three
things: (a) the real decoder ACCEPTS it and returns ``tid`` "t-1"; (b) a tampered
signature and a wrong key are REJECTED; (c) we independently reconstruct the
signing input + HMAC and assert the recomputed signature segment equals the
vector's — so the byte format itself is pinned, not merely a round-trip.

Stdlib only. The "key" here is a throwaway TEST constant, never a real secret.
"""
import base64
import hashlib
import hmac
import json
import unittest

from glyph_relay.auth import decode_broker_token


# --- Shared cross-repo test vector (must byte-match glyph-hosted's vector) ----
SHARED_KEY = b"test-shared-key"
KID = "v1"
PAYLOAD = {"tid": "t-1", "exp": 9999999999, "iat": 1}
# Canonical token string. If glyph-relay's decoder or glyph-hosted's encoder drift,
# one of the assertions below breaks and CI fails.
EXPECTED_TOKEN = (
    "v1.eyJ0aWQiOiJ0LTEiLCJleHAiOjk5OTk5OTk5OTksImlhdCI6MX0"
    ".4lUH9B69mEQXcq6cogGISZKPQ_f7Sly8bDyb4Oo6-y4"
)
KEYS = {KID: SHARED_KEY}
# ``now`` is strictly before ``exp`` (the vector never expires for the test); the
# vector's own ``iat`` is a convenient in-window clock value.
NOW = 1


def _b64url_nopad(raw):
    """Encode ``raw`` bytes as unpadded base64url (the broker-token convention)."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class BrokerTokenVectorTests(unittest.TestCase):
    def test_decoder_accepts_exact_vector_returns_tid(self):
        # (a) The real decoder ACCEPTS the canonical token and yields tid "t-1".
        tid = decode_broker_token(EXPECTED_TOKEN, KEYS, NOW, set())
        self.assertEqual(tid, "t-1")

    def test_tampered_signature_rejected(self):
        # (b1) Flip the last signature char: signature no longer matches -> reject.
        kid, payload_b64, sig_b64 = EXPECTED_TOKEN.split(".")
        bad_last = "A" if sig_b64[-1] != "A" else "B"
        tampered = "{0}.{1}.{2}".format(kid, payload_b64, sig_b64[:-1] + bad_last)
        self.assertIsNone(decode_broker_token(tampered, KEYS, NOW, set()))

    def test_tampered_payload_rejected(self):
        # (b2) Re-sign-free payload edit: swap tid bytes without re-signing -> reject.
        forged_payload = _b64url_nopad(
            json.dumps({"tid": "t-2", "exp": 9999999999, "iat": 1},
                       separators=(",", ":")).encode("utf-8"))
        _, _, sig_b64 = EXPECTED_TOKEN.split(".")
        forged = "{0}.{1}.{2}".format(KID, forged_payload, sig_b64)
        self.assertIsNone(decode_broker_token(forged, KEYS, NOW, set()))

    def test_wrong_key_rejected(self):
        # (b3) Same token, different verification key -> signature mismatch -> reject.
        self.assertIsNone(
            decode_broker_token(EXPECTED_TOKEN, {KID: b"not-the-key"}, NOW, set()))

    def test_unknown_kid_rejected(self):
        # (b4) The token's kid is absent from the key map -> reject (no key to use).
        self.assertIsNone(
            decode_broker_token(EXPECTED_TOKEN, {"v2": SHARED_KEY}, NOW, set()))

    def test_independent_signature_reconstruction_matches_vector(self):
        # (c) Rebuild the signing input + HMAC from first principles and assert the
        #     recomputed signature segment equals the vector's third segment. This
        #     pins the BYTE FORMAT (key order, compact JSON, b64url-no-pad, the
        #     "kid.payload" signing string), independent of the decoder.
        payload_json = json.dumps(PAYLOAD, separators=(",", ":")).encode("utf-8")
        payload_b64 = _b64url_nopad(payload_json)
        signing_input = (KID + "." + payload_b64).encode("utf-8")
        sig = hmac.new(SHARED_KEY, signing_input, hashlib.sha256).digest()
        sig_b64 = _b64url_nopad(sig)

        recomputed_token = "{0}.{1}.{2}".format(KID, payload_b64, sig_b64)
        self.assertEqual(recomputed_token, EXPECTED_TOKEN)

        # And specifically the signature segment matches the pinned vector's.
        self.assertEqual(sig_b64, EXPECTED_TOKEN.split(".")[2])

    def test_payload_segment_matches_vector(self):
        # The middle segment is the compact, key-ordered JSON; pin it too so a
        # drift to sort_keys / spaces / different field order is caught.
        payload_json = json.dumps(PAYLOAD, separators=(",", ":")).encode("utf-8")
        self.assertEqual(_b64url_nopad(payload_json), EXPECTED_TOKEN.split(".")[1])

    def test_denylisted_tid_rejected(self):
        # Defence-in-depth: a valid signature for a revoked tenant is still rejected.
        self.assertIsNone(
            decode_broker_token(EXPECTED_TOKEN, KEYS, NOW, {"t-1"}))


if __name__ == "__main__":
    unittest.main()
