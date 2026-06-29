# SPDX-License-Identifier: Elastic-2.0
"""Per-user revocable relay enrollment: a stdlib sqlite3 credential registry
(hashed at rest) plus the admin CLI. See docs/specs/multi-tenant-hosted-relay.md (§1).

The relay verifies an ``X-Relay-Enroll: <id>.<secret>`` header against this registry
(constant-cost, timing-equalized) and reaps live sessions minted under a revoked or
expired credential. The CLI (add/list/revoke/rotate) is the only writer and the relay
process is a reader -- the two run as separate processes against the same sqlite file,
so every access uses a short-lived WAL connection (concurrent reader + writer safe, and
safe across the relay's verify executor threads vs. its reaper loop thread).

Secrets are never stored in the clear: only a per-row PBKDF2 hash + salt + iteration
count are persisted. The plaintext secret is shown once, at creation/rotation.
"""
import argparse
import hashlib
import hmac
import sqlite3
import sys
import time
from datetime import datetime, timezone

import secrets as _secrets


DEFAULT_DB = "var/enrollments.db"
# PBKDF2 iterations for hashing the enrollment secret at rest. The secret is a
# token_urlsafe(32) value -- 256 bits of entropy, NOT a human password -- so offline
# brute force is infeasible at ANY work factor. A large iteration count would add no
# real at-rest protection while turning the unauthenticated POST /session path into a
# CPU-amplification vector (one cheap request -> one full KDF, before the rate limiter).
# So we keep a MODEST count purely for hash-at-rest hygiene. verify() still runs in a
# thread executor so the event loop never stalls, and a public relay should additionally
# rely on edge rate-limiting (see docs/runbook.md).
# NOTE: the per-row `iters` column lets the work factor evolve, but raising DEFAULT_ITERS
# while old rows keep their lower count would make verify()'s dummy path (self.iters) and
# the real path (row `iters`) diverge in time -- re-issue credentials after any bump to
# preserve timing uniformity.
DEFAULT_ITERS = 1000
_SALT_BYTES = 16
_SECRET_BYTES = 32
_ID_BYTES = 8
# Fixed dummy salt so an unknown/malformed id still costs exactly one pbkdf2 -- no
# timing oracle answering "is this id enrolled?".
_DUMMY_SALT = b"\x00" * _SALT_BYTES


def _connect(path):
    # timeout=5.0 installs sqlite's busy handler so transient write contention between
    # the relay (reader) and the CLI (writer) blocks briefly instead of raising.
    conn = sqlite3.connect(path, timeout=5.0)
    # Switching a fresh DB INTO WAL needs a short EXCLUSIVE lock that the busy handler
    # does NOT cover, so two processes first-touching the same new file can collide with
    # "database is locked". WAL is a persistent property of the file once set, so a
    # transient failure self-heals on a later connect; retry briefly, then proceed
    # (correctness still holds in the default rollback-journal mode, whose ordinary lock
    # contention the busy handler DOES cover).
    for _ in range(10):
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            break
        except sqlite3.OperationalError:
            time.sleep(0.05)
    return conn


class EnrollmentRegistry:
    """SQLite-backed per-user credential registry (stdlib only, hashed at rest)."""

    def __init__(self, path=DEFAULT_DB, iters=DEFAULT_ITERS):
        self.path = path
        self.iters = iters
        conn = _connect(path)
        try:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS enrollments ("
                "id TEXT PRIMARY KEY, label TEXT NOT NULL, salt BLOB NOT NULL, "
                "hash BLOB NOT NULL, iters INTEGER NOT NULL, created_at REAL NOT NULL, "
                "expires_at REAL, revoked_at REAL, "
                "keep_sessions INTEGER NOT NULL DEFAULT 0)")
            conn.commit()
        finally:
            conn.close()

    def _hash(self, secret, salt, iters):
        return hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, iters)

    # ---- write operations (admin CLI is the only writer) ----

    def add(self, label, expires_at=None, now=None):
        """Mint a credential; return (id, secret). The secret is shown once."""
        if now is None:
            now = time.time()
        ident = _secrets.token_hex(_ID_BYTES)
        secret = _secrets.token_urlsafe(_SECRET_BYTES)
        salt = _secrets.token_bytes(_SALT_BYTES)
        digest = self._hash(secret, salt, self.iters)
        conn = _connect(self.path)
        try:
            conn.execute(
                "INSERT INTO enrollments (id, label, salt, hash, iters, created_at, "
                "expires_at, revoked_at, keep_sessions) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 0)",
                (ident, label, salt, digest, self.iters, now, expires_at))
            conn.commit()
        finally:
            conn.close()
        return ident, secret

    def revoke(self, ident, keep_sessions=False, now=None):
        """Mark a credential revoked. Returns True if the id exists.

        Idempotent: the first revoke time is preserved (COALESCE) while keep_sessions
        is always updated, so a later ``revoke --keep-sessions`` can spare live sessions."""
        if now is None:
            now = time.time()
        conn = _connect(self.path)
        try:
            cur = conn.execute(
                "UPDATE enrollments SET revoked_at = COALESCE(revoked_at, ?), "
                "keep_sessions = ? WHERE id = ?",
                (now, 1 if keep_sessions else 0, ident))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    def rotate(self, ident, now=None):
        """Swap the secret in place (new salt+hash). Revoke/expiry state untouched
        (rotate is orthogonal to revoke). Return the new secret, or None if no such id."""
        secret = _secrets.token_urlsafe(_SECRET_BYTES)
        salt = _secrets.token_bytes(_SALT_BYTES)
        digest = self._hash(secret, salt, self.iters)
        conn = _connect(self.path)
        try:
            cur = conn.execute(
                "UPDATE enrollments SET salt = ?, hash = ?, iters = ? WHERE id = ?",
                (salt, digest, self.iters, ident))
            conn.commit()
            if cur.rowcount == 0:
                return None
            return secret
        finally:
            conn.close()

    def list_all(self):
        """All rows as dicts, oldest first. Deliberately omits salt/hash so no secret
        material can leak through the audit path."""
        conn = _connect(self.path)
        try:
            cur = conn.execute(
                "SELECT id, label, created_at, expires_at, revoked_at, keep_sessions "
                "FROM enrollments ORDER BY created_at, id")
            rows = cur.fetchall()
        finally:
            conn.close()
        return [{"id": r[0], "label": r[1], "created_at": r[2], "expires_at": r[3],
                 "revoked_at": r[4], "keep_sessions": bool(r[5])} for r in rows]

    # ---- read operations (relay) ----

    def verify(self, ident, secret, now):
        """Constant-cost credential check. Return the enrollment id on success, else None.

        Always performs exactly one pbkdf2 -- real for a known id, dummy for an unknown
        or malformed one -- so response time never reveals whether ``ident`` is enrolled,
        revoked, or expired. Caller passes wall-clock ``now`` (revocation/expiry clock)."""
        if not isinstance(ident, str) or not isinstance(secret, str):
            self._hash("", _DUMMY_SALT, self.iters)   # pay the cost; no fast-path oracle
            return None
        conn = _connect(self.path)
        try:
            cur = conn.execute(
                "SELECT salt, hash, iters, expires_at, revoked_at "
                "FROM enrollments WHERE id = ?", (ident,))
            row = cur.fetchone()
        finally:
            conn.close()
        if row is None:
            self._hash(secret, _DUMMY_SALT, self.iters)   # dummy: cost ~= a real verify
            return None
        salt, stored_hash, iters, expires_at, revoked_at = row
        candidate = self._hash(secret, salt, iters)
        secret_ok = hmac.compare_digest(candidate, stored_hash)
        active = revoked_at is None and (expires_at is None or expires_at > now)
        if secret_ok and active:
            return ident
        return None

    def reapable_ids(self, now):
        """Ids whose live sessions should be torn down: revoked (without keep_sessions)
        or expired. Caller passes wall-clock ``now``."""
        conn = _connect(self.path)
        try:
            cur = conn.execute(
                "SELECT id FROM enrollments WHERE "
                "(revoked_at IS NOT NULL AND keep_sessions = 0) "
                "OR (expires_at IS NOT NULL AND expires_at <= ?)", (now,))
            rows = cur.fetchall()
        finally:
            conn.close()
        return {r[0] for r in rows}


# --------------------------------------------------------------------------- CLI

_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
_MAX_EXPIRY_SECONDS = 100 * 365 * 86400   # ~100 years; rejects absurd/overflowing inputs


def parse_expires(value, now):
    """Parse --expires into an absolute wall-clock epoch.

    Accepts a duration relative to ``now`` (30d / 12h / 90m / 45s / 2w) or an ISO-8601
    absolute time (naive is interpreted as UTC). Raises ValueError on malformed input."""
    value = value.strip()
    if not value:
        raise ValueError("empty --expires")
    unit = value[-1].lower()
    if unit in _DURATION_UNITS and value[:-1].isdigit():
        amount = int(value[:-1])
        if amount <= 0:
            raise ValueError("duration must be positive")
        seconds = amount * _DURATION_UNITS[unit]
        if seconds > _MAX_EXPIRY_SECONDS:   # bound it (also avoids a float OverflowError)
            raise ValueError("duration too large (max ~100 years)")
        return now + seconds
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        raise ValueError(
            "not a duration (e.g. 30d) or ISO-8601 time: {0!r}".format(value))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _fmt_time(epoch):
    if epoch is None:
        return "-"
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _status(row, now):
    if row["revoked_at"] is not None:
        return "revoked"
    if row["expires_at"] is not None and row["expires_at"] <= now:
        return "expired"
    return "active"


def _cmd_add(reg, args, now, out):
    expires_at = parse_expires(args.expires, now) if args.expires else None
    ident, secret = reg.add(args.label, expires_at=expires_at, now=now)
    out.write("{0}.{1}\n".format(ident, secret))
    out.write("# id={0} label={1!r} -- store this secret now; it is not recoverable.\n"
              .format(ident, args.label))
    return 0


def _cmd_list(reg, args, now, out):
    rows = reg.list_all()
    if not rows:
        out.write("(no enrollments)\n")
        return 0
    fmt = "{0:<18} {1:<8} {2:<22} {3:<22} {4}\n"
    out.write(fmt.format("id", "status", "created", "expires", "label"))
    for r in rows:
        out.write(fmt.format(r["id"], _status(r, now), _fmt_time(r["created_at"]),
                             _fmt_time(r["expires_at"]), r["label"]))
    return 0


def _cmd_revoke(reg, args, now, out):
    if not reg.revoke(args.id, keep_sessions=args.keep_sessions, now=now):
        out.write("no such enrollment id: {0}\n".format(args.id))
        return 1
    note = " (live sessions kept)" if args.keep_sessions else " (live sessions reaped)"
    out.write("revoked {0}{1}\n".format(args.id, note))
    return 0


def _cmd_rotate(reg, args, now, out):
    secret = reg.rotate(args.id, now=now)
    if secret is None:
        out.write("no such enrollment id: {0}\n".format(args.id))
        return 1
    out.write("{0}.{1}\n".format(args.id, secret))
    out.write("# rotated {0} -- distribute the new secret; the old one no longer works.\n"
              .format(args.id))
    return 0


_COMMANDS = {"add": _cmd_add, "list": _cmd_list,
             "revoke": _cmd_revoke, "rotate": _cmd_rotate}


def build_parser():
    parser = argparse.ArgumentParser(
        prog="python3 -m glyph_relay.enrollment",
        description="Manage per-user revocable relay enrollment credentials (#140).")
    parser.add_argument("--db", default=DEFAULT_DB,
                        help="enrollment registry path (default {0})".format(DEFAULT_DB))
    sub = parser.add_subparsers(dest="command", required=True)

    p_add = sub.add_parser("add", help="mint a credential; prints id.secret once")
    p_add.add_argument("--label", required=True, help="human audit label")
    p_add.add_argument("--expires", default=None,
                       help="duration (30d/12h/90m/45s/2w) or ISO-8601 UTC time")

    sub.add_parser("list", help="list enrollments (never prints secrets)")

    p_rev = sub.add_parser("revoke", help="revoke a credential")
    p_rev.add_argument("id", help="enrollment id to revoke")
    p_rev.add_argument("--keep-sessions", action="store_true",
                       help="block new sessions but leave live ones running")

    p_rot = sub.add_parser("rotate", help="rotate a credential's secret in place")
    p_rot.add_argument("id", help="enrollment id to rotate")
    return parser


def main(argv=None, out=None, now=None):
    if out is None:
        out = sys.stdout
    if now is None:
        now = time.time()
    args = build_parser().parse_args(argv)
    reg = EnrollmentRegistry(args.db)
    try:
        return _COMMANDS[args.command](reg, args, now, out)
    except (ValueError, OverflowError) as exc:
        out.write("error: {0}\n".format(exc))
        return 2


if __name__ == "__main__":
    sys.exit(main())
