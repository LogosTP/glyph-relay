# SPDX-License-Identifier: Elastic-2.0
"""Select self-host vs hosted wiring from environment. One codebase, two modes.

- ``selfhost`` — a single statically-configured MUD target, a RAM-only Hub, and an
  open-or-gated enrollment. The gate is either a global shared secret
  (``GLYPH_ENROLL_SECRET`` -> ``StaticEnrollAuth``) or, when ``RELAY_ENROLL_DB`` is
  set, the per-user #140 ``EnrollmentRegistry`` (revocable credentials + reaper). No
  admin surface, no durable history.
- ``hosted`` — per-tenant ``BrokerTokenAuth`` (HMAC broker token), a durable
  ``HistoryStore`` sunk into every session's Hub, per-tenant quotas, an SSRF target
  allowlist, and the ``X-Relay-Admin`` revoke/purge surface.

All hosted behaviour is additive and off in self-host.
"""
from .relay import Relay
from .sessions import SessionManager
from .auth import StaticEnrollAuth, BrokerTokenAuth


def _flag(env, name, default=False):
    val = env.get(name)
    if val is None:
        return default
    return str(val).strip().lower() in ("1", "true", "yes", "on")


def _int(env, name, default):
    try:
        return int(env[name])
    except (KeyError, ValueError, TypeError):
        return default


def build_relay(mode, env):
    """Build a ready-to-start ``Relay`` for ``mode`` ("selfhost" | "hosted")."""
    relay_host = env.get("RELAY_HOST", "127.0.0.1")
    relay_port = _int(env, "RELAY_PORT", 8765)
    idle_ttl = float(env["IDLE_TTL"]) if env.get("IDLE_TTL") else 1800.0
    session_rate = _int(env, "SESSION_RATE", 0) or None
    session_window = float(env.get("SESSION_WINDOW", "60"))

    if mode == "hosted":
        keys = {env["SHARED_HMAC_KID"]: env["SHARED_HMAC_KEY"].encode("utf-8")}
        denylist = set()
        from .history import HistoryStore
        history = HistoryStore(env["HISTORY_DB"])
        allowlist = None
        if env.get("RELAY_TARGET_ALLOWLIST"):
            from .targets import load_allowlist_file
            allowlist = load_allowlist_file(env["RELAY_TARGET_ALLOWLIST"])
        target_ports = None
        if env.get("RELAY_TARGET_PORTS"):       # "lo-hi"
            lo, _, hi = env["RELAY_TARGET_PORTS"].partition("-")
            target_ports = (int(lo), int(hi))
        manager = SessionManager(
            host=env.get("MUD_HOST", "-"), port=_int(env, "MUD_PORT", 0),
            use_tls=_flag(env, "MUD_TLS", True),
            max_user_sessions=_int(env, "MAX_SESSIONS", 200),
            max_sessions_per_tenant=_int(env, "MAX_PER_TENANT", 5),
            idle_ttl=idle_ttl, history=history)
        return Relay(
            manager=manager, host=relay_host, port=relay_port,
            authenticator=BrokerTokenAuth(keys, denylist),
            admin_secret=env["RELAY_ADMIN_SECRET"], denylist=denylist, history=history,
            target_allowlist=allowlist, target_ports=target_ports,
            session_rate=session_rate, session_window=session_window)

    if mode != "selfhost":
        raise ValueError("unknown relay mode: {0!r}".format(mode))

    # selfhost: single target, RAM-only history, no admin.
    enroll_db = env.get("RELAY_ENROLL_DB")
    enroll_registry = None
    authenticator = None
    if enroll_db:
        # Per-user revocable enrollment (#140) — the registry gates POST /session and
        # the reaper tears down revoked sessions. No global shared-secret authenticator.
        from .enrollment import EnrollmentRegistry
        enroll_registry = EnrollmentRegistry(enroll_db)
    else:
        # Global shared secret (or open when unset): StaticEnrollAuth tags tenant "self".
        authenticator = StaticEnrollAuth(env.get("GLYPH_ENROLL_SECRET"))
    manager = SessionManager(
        host=env.get("MUD_HOST", "127.0.0.1"), port=_int(env, "MUD_PORT", 4000),
        use_tls=_flag(env, "MUD_TLS", False), ca_file=env.get("MUD_CA_FILE"),
        max_user_sessions=_int(env, "MAX_SESSIONS", 20), idle_ttl=idle_ttl,
        enroll_registry=enroll_registry)
    return Relay(
        manager=manager, host=relay_host, port=relay_port,
        authenticator=authenticator, enroll_registry=enroll_registry,
        session_rate=session_rate, session_window=session_window)
