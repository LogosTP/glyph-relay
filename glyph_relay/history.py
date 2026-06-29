# SPDX-License-Identifier: Elastic-2.0
"""Durable per-tenant session history (SQLite) — spec §3.

The ``Hub`` sinks every published event into this append-only store at
``publish()`` time, AFTER id assignment and AFTER ``_scrub`` masking (the sink only
ever sees ``********``-masked payloads — raw secrets are never persisted), so
history survives the RAM ring trim and logout. Catch-up reads beyond the ~500-event
RAM window come from here, and ``export``/``delete`` are tenant-scoped for
admin-purge + GDPR-style erase.

Encryption at rest is OPERATIONAL (disk/volume: FileVault/LUKS), keeping this module
stdlib-only. Tenant isolation is enforced by always filtering on ``tenant_id``.
"""
import json
import sqlite3


class HistoryStore:
    def __init__(self, path):
        # check_same_thread=False: the relay verifies/sinks from executor threads and
        # the loop thread. Access is serialized by the GIL + short statements; sqlite's
        # own locking covers the rest. A file path persists; ":memory:" is for tests.
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS events ("
            "tenant_id TEXT NOT NULL, session_key TEXT NOT NULL, "
            "event_id INTEGER NOT NULL, kind TEXT NOT NULL, data TEXT NOT NULL, "
            "ts REAL NOT NULL DEFAULT (strftime('%s','now')), "
            "PRIMARY KEY (tenant_id, session_key, event_id))")
        self.db.commit()

    def append(self, tenant_id, session_key, event_id, kind, data):
        # INSERT OR IGNORE: the (tenant, session, event_id) PK means a replayed or
        # forged id can never overwrite an existing relay-assigned event.
        self.db.execute(
            "INSERT OR IGNORE INTO events"
            "(tenant_id,session_key,event_id,kind,data) VALUES(?,?,?,?,?)",
            (tenant_id, session_key, event_id, kind,
             json.dumps(data, separators=(",", ":"), ensure_ascii=False)))
        self.db.commit()

    def backlog(self, tenant_id, session_key, since_id=None):
        cur = self.db.execute(
            "SELECT event_id,kind,data FROM events "
            "WHERE tenant_id=? AND session_key=? AND event_id>? ORDER BY event_id",
            (tenant_id, session_key, since_id if since_id is not None else -1))
        return [(eid, kind, json.loads(data)) for (eid, kind, data) in cur.fetchall()]

    def max_event_id(self, tenant_id, session_key):
        """Highest persisted event id for a session, or ``None`` if empty.

        Used to seed ``Hub._next_id`` so ids don't rewind across restarts (§3.1)."""
        cur = self.db.execute(
            "SELECT MAX(event_id) FROM events WHERE tenant_id=? AND session_key=?",
            (tenant_id, session_key))
        row = cur.fetchone()
        return row[0] if row is not None else None

    def export(self, tenant_id):
        cur = self.db.execute(
            "SELECT session_key,event_id,kind,data FROM events "
            "WHERE tenant_id=? ORDER BY session_key,event_id", (tenant_id,))
        return [{"session_key": sk, "event_id": eid, "kind": kind, "data": json.loads(data)}
                for (sk, eid, kind, data) in cur.fetchall()]

    def delete(self, tenant_id):
        cur = self.db.execute("DELETE FROM events WHERE tenant_id=?", (tenant_id,))
        self.db.commit()
        return cur.rowcount

    def close(self):
        self.db.close()
