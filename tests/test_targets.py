# SPDX-License-Identifier: Elastic-2.0
"""Outbound-target SSRF guard + DNS-rebind pinning (spec §2.2)."""
import unittest

from glyph_relay.targets import is_allowed_target, load_allowlist


def _resolver(ip):
    return lambda host: ip


class TargetSafetyTests(unittest.TestCase):
    def test_public_mud_allowed_returns_pinned_ip(self):
        # Allowed targets return the PINNED ip (truthy), not just True, so the caller
        # connects to the resolved address (DNS-rebind defense).
        self.assertEqual(
            is_allowed_target("mud.example.com", 4000, resolver=_resolver("8.8.8.8")),
            "8.8.8.8")

    def test_loopback_blocked(self):
        self.assertIsNone(
            is_allowed_target("localhost", 4000, resolver=_resolver("127.0.0.1")))
        self.assertIsNone(
            is_allowed_target("localhost6", 4000, resolver=_resolver("::1")))

    def test_private_blocked(self):
        for ip in ("10.0.0.5", "192.168.1.1", "172.16.5.5"):
            self.assertIsNone(
                is_allowed_target("internal", 4000, resolver=_resolver(ip)))

    def test_ipv6_ula_blocked(self):
        self.assertIsNone(
            is_allowed_target("internal", 4000, resolver=_resolver("fd00::1")))

    def test_link_local_metadata_blocked(self):
        self.assertIsNone(
            is_allowed_target("meta", 80, resolver=_resolver("169.254.169.254")))
        self.assertIsNone(
            is_allowed_target("meta", 4000, resolver=_resolver("fe80::1")))

    def test_cgnat_blocked(self):
        # CGNAT / shared address space (100.64.0.0/10) is a tailnet/NAT range and must
        # be blocked explicitly (older ipaddress builds don't flag it is_private).
        self.assertIsNone(
            is_allowed_target("tailnet", 4000, resolver=_resolver("100.64.0.1")))
        self.assertIsNone(
            is_allowed_target("tailnet", 4000, resolver=_resolver("100.127.255.254")))

    def test_multicast_reserved_unspecified_blocked(self):
        for ip in ("224.0.0.1", "240.0.0.1", "0.0.0.0"):
            self.assertIsNone(
                is_allowed_target("x", 4000, resolver=_resolver(ip)))

    def test_low_privileged_port_blocked_except_telnet(self):
        self.assertIsNone(
            is_allowed_target("mud.example.com", 22, resolver=_resolver("8.8.8.8")))
        self.assertEqual(
            is_allowed_target("mud.example.com", 23, resolver=_resolver("8.8.8.8")),
            "8.8.8.8")

    def test_out_of_range_or_non_int_port_blocked(self):
        for port in (0, 65536, -1, "4000", None, 4000.5):
            self.assertIsNone(
                is_allowed_target("mud.example.com", port, resolver=_resolver("8.8.8.8")))

    def test_operator_port_window_tightens(self):
        # An operator may narrow the allowed range; 4000 in, 5000 out.
        self.assertEqual(
            is_allowed_target("mud.example.com", 4000, resolver=_resolver("8.8.8.8"),
                              ports=(3000, 4999)), "8.8.8.8")
        self.assertIsNone(
            is_allowed_target("mud.example.com", 5000, resolver=_resolver("8.8.8.8"),
                              ports=(3000, 4999)))

    def test_unresolvable_blocked_fail_closed(self):
        def boom(host):
            raise OSError("nxdomain")
        self.assertIsNone(
            is_allowed_target("nope.invalid", 4000, resolver=boom))

    def test_host_allowlist_enforced_when_set(self):
        allow = load_allowlist(["mud.example.com", "other.example:5000"])
        # In the allowlist -> allowed.
        self.assertEqual(
            is_allowed_target("mud.example.com", 4000, resolver=_resolver("8.8.8.8"),
                              allowlist=allow), "8.8.8.8")
        # Not in the allowlist -> blocked even though the IP/port are otherwise fine.
        self.assertIsNone(
            is_allowed_target("evil.example.com", 4000, resolver=_resolver("8.8.8.8"),
                              allowlist=allow))
        # host:port entry pins the port too.
        self.assertEqual(
            is_allowed_target("other.example", 5000, resolver=_resolver("8.8.4.4"),
                              allowlist=allow), "8.8.4.4")
        self.assertIsNone(
            is_allowed_target("other.example", 4000, resolver=_resolver("8.8.4.4"),
                              allowlist=allow))  # wrong port for a host:port entry

    def test_allowlist_does_not_override_ssrf(self):
        # Even an allowlisted host must still pass the IP guard (rebind protection).
        allow = load_allowlist(["mud.example.com"])
        self.assertIsNone(
            is_allowed_target("mud.example.com", 4000, resolver=_resolver("127.0.0.1"),
                              allowlist=allow))


if __name__ == "__main__":
    unittest.main()
