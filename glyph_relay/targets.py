# SPDX-License-Identifier: Elastic-2.0
"""Outbound-connection allowlist + DNS-rebind pinning (spec §2.2).

The hosted relay opens TCP to user-supplied MUD targets, so every target must be
bounded:

- **Port:** deny ``< 1024`` except 23 (telnet); deny non-int / out of 1..65535. An
  operator may tighten the window via ``ports=(lo, hi)``.
- **Resolved IP:** resolve the host ONCE, then deny loopback / private / link-local
  (incl. ``169.254.169.254`` metadata) / CGNAT ``100.64.0.0/10`` / multicast /
  reserved / unspecified. Deny on resolution failure (fail closed).
- **DNS-rebind defense:** ``is_allowed_target`` returns the *pinned IP* it resolved.
  The caller connects to THAT ip (with SNI = the original host), so a TOCTOU rebind
  between the check and the connect cannot redirect the socket.
- **Operator host allowlist (optional):** when ``allowlist`` is set, the target host
  (and, for ``host:port`` entries, the port) must match.

Pure except for the default DNS resolver; ``resolver`` is injectable for tests.
"""
import ipaddress
import socket

# CGNAT / shared address space (RFC 6598). Some ipaddress builds don't flag it as
# private, so block it explicitly.
_CGNAT_V4 = ipaddress.ip_network("100.64.0.0/10")
# The cloud metadata endpoint (link-local, but pin it by value too as belt-and-braces).
_METADATA = ipaddress.ip_address("169.254.169.254")


def _default_resolver(host):
    """First resolved address for ``host`` (A or AAAA). Raises OSError on failure."""
    return socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)[0][4][0]


def _ip_is_safe(ip):
    """True iff ``ip`` (an ipaddress object) is a routable, public unicast address."""
    if ip == _METADATA or ip in _CGNAT_V4 and ip.version == 4:
        return False
    if (ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast
            or ip.is_reserved or ip.is_unspecified):
        return False
    # IPv4-mapped IPv6 (::ffff:127.0.0.1) must be judged on the embedded v4 address.
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        return _ip_is_safe(mapped)
    return True


def load_allowlist(lines):
    """Parse host / host:port allowlist lines into a lookup structure.

    Returns ``{host_lower: set_of_ports_or_None}``: a value of ``None`` means any
    port for that host; a non-empty set means only those ports. Blank lines and
    ``#`` comments are ignored."""
    hosts = {}
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        host, sep, port = line.partition(":")
        host = host.strip().lower()
        if not host:
            continue
        if sep and port.strip():
            try:
                p = int(port.strip())
            except ValueError:
                continue
            existing = hosts.get(host)
            if existing is None and host in hosts:
                # A bare-host entry already allowed any port; keep it permissive.
                continue
            hosts.setdefault(host, set())
            if hosts[host] is not None:
                hosts[host].add(p)
        else:
            hosts[host] = None  # bare host: any port
    return hosts


def load_allowlist_file(path):
    """Read an allowlist file (host or host:port per line) into ``load_allowlist``."""
    with open(path, "r", encoding="utf-8") as f:
        return load_allowlist(f.readlines())


def _host_allowed(host, port, allowlist):
    if allowlist is None:
        return True
    ports = allowlist.get(host.lower(), _MISSING)
    if ports is _MISSING:
        return False
    return ports is None or port in ports


_MISSING = object()


def is_allowed_target(host, port, *, resolver=None, allowlist=None, ports=None):
    """Return the pinned IP (str) for an allowed target, else ``None``.

    ``ports`` optionally tightens the default port policy to ``(lo, hi)``. ``allowlist``
    is the structure from ``load_allowlist`` (or ``None`` for IP/port rules only)."""
    resolver = resolver or _default_resolver
    # bool is an int subclass but must not pass as a port; reject it and floats.
    if isinstance(port, bool) or not isinstance(port, int):
        return None
    if not (1 <= port <= 65535):
        return None
    if ports is not None:
        lo, hi = ports
        if not (lo <= port <= hi):
            return None
    elif port < 1024 and port != 23:   # default: allow telnet (23), deny other privileged
        return None
    if not _host_allowed(host, port, allowlist):
        return None
    try:
        ip_str = resolver(host)
        ip = ipaddress.ip_address(ip_str)
    except (OSError, ValueError):
        return None
    if not _ip_is_safe(ip):
        return None
    return ip_str
