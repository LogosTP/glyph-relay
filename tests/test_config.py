# SPDX-License-Identifier: Elastic-2.0
"""build_relay mode selection (Task 9): self-host vs hosted wiring from env."""
import unittest

from glyph_relay.config import build_relay
from glyph_relay.auth import StaticEnrollAuth, BrokerTokenAuth


class BuildConfigTests(unittest.TestCase):
    def test_selfhost_has_no_admin_and_static_auth(self):
        r = build_relay("selfhost", {"GLYPH_ENROLL_SECRET": "s"})
        self.assertIsInstance(r.authenticator, StaticEnrollAuth)
        self.assertIsNone(r.admin_secret)
        self.assertIsNone(r.history)
        try:
            self.addCleanup(lambda: None)
        finally:
            pass

    def test_selfhost_open_when_no_secret(self):
        r = build_relay("selfhost", {})
        self.assertIsInstance(r.authenticator, StaticEnrollAuth)
        self.assertIsNone(r.authenticator.secret)   # open

    def test_selfhost_enroll_db_uses_registry_not_static(self):
        import os
        import tempfile
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        r = build_relay("selfhost", {"RELAY_ENROLL_DB": os.path.join(d.name, "e.db")})
        self.assertIsNone(r.authenticator)            # registry path, not static auth
        self.assertIsNotNone(r.enroll_registry)
        self.assertIsNotNone(r.manager.enroll_registry)

    def test_hosted_has_broker_auth_admin_and_history(self):
        env = {"SHARED_HMAC_KEY": "k", "SHARED_HMAC_KID": "v1",
               "RELAY_ADMIN_SECRET": "adm", "HISTORY_DB": ":memory:"}
        r = build_relay("hosted", env)
        self.assertIsInstance(r.authenticator, BrokerTokenAuth)
        self.assertEqual(r.admin_secret, "adm")
        self.assertIsNotNone(r.history)
        self.assertIs(r.manager.history, r.history)   # the session sink is wired
        self.addCleanup(r.history.close)

    def test_hosted_threads_key_and_denylist(self):
        env = {"SHARED_HMAC_KEY": "k", "SHARED_HMAC_KID": "v7",
               "RELAY_ADMIN_SECRET": "adm", "HISTORY_DB": ":memory:"}
        r = build_relay("hosted", env)
        self.assertEqual(r.authenticator.keys, {"v7": b"k"})
        # The denylist the authenticator reads is the SAME set admin revoke mutates.
        self.assertIs(r.authenticator.denylist, r.denylist)
        self.assertEqual(r.manager.max_sessions_per_tenant, 5)  # default per-tenant cap
        self.addCleanup(r.history.close)

    def test_unknown_mode_raises(self):
        with self.assertRaises(ValueError):
            build_relay("bogus", {})


if __name__ == "__main__":
    unittest.main()
