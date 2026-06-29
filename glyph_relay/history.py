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
    def __init__(self, path, max_rows_per_session=None):
        # check_same_thread=False: the relay verifies/sinks from executor threads and
        # the loop thread. Access is serialized by the GIL + short statements; sqlite's
        # own locking covers the rest. A file path persists; ":memory:" is for tests.
        self.db = sqlite3.connect(path, check_same_thread=False)
        # WAL + synchronous=NORMAL: a per-row commit is cheap (no full fsync each write,
        # one concurrent reader + writer), so the synchronous commit in the publish sink
        # doesn't stall the asyncio loop. Crash-safe enough for a transcript: at most the
        # last few un-checkpointed events are lost on power loss, never DB corruption.
        # (:memory: ignores WAL and stays "memory" — harmless; the bound below still holds.)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        # Per-(tenant, session) durable-history bound (ring). None = unbounded. When set,
        # append/append_many prune the oldest rows so one session cannot grow the shared
        # SQLite file without limit (DoS bound; combine with the ingest rate limit).
        self.max_rows_per_session = max_rows_per_session
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS events ("
            "tenant_id TEXT NOT NULL, session_key TEXT NOT NULL, "
            "event_id INTEGER NOT NULL, kind TEXT NOT NULL, data TEXT NOT NULL, "
            "ts REAL NOT NULL DEFAULT (strftime('%s','now')), "
            "PRIMARY KEY (tenant_id, session_key, event_id))")
        self.db.commit()

    def _encode(self, data):
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)

    def _prune(self, tenant_id, session_key):
        """Drop rows older than the newest ``max_rows_per_session`` for this session.

        Event ids are dense + monotonic per session, so "keep the last N" == "delete
        where event_id <= max-N" — a single PK-range DELETE (no COUNT scan). No-op when
        unbounded or under the cap. The caller commits."""
        cap = self.max_rows_per_session
        if cap is None:
            return
        row = self.db.execute(
            "SELECT MAX(event_id) FROM events WHERE tenant_id=? AND session_key=?",
            (tenant_id, session_key)).fetchone()
        if row is None or row[0] is None:
            return
        self.db.execute(
            "DELETE FROM events WHERE tenant_id=? AND session_key=? AND event_id<=?",
            (tenant_id, session_key, row[0] - cap))

    def append(self, tenant_id, session_key, event_id, kind, data):
        # INSERT OR IGNORE: the (tenant, session, event_id) PK means a replayed or
        # forged id can never overwrite an existing relay-assigned event.
        self.db.execute(
            "INSERT OR IGNORE INTO events"
            "(tenant_id,session_key,event_id,kind,data) VALUES(?,?,?,?,?)",
            (tenant_id, session_key, event_id, kind, self._encode(data)))
        self._prune(tenant_id, session_key)
        self.db.commit()

    def append_many(self, tenant_id, session_key, rows):
        """Persist a batch of (event_id, kind, data) in ONE executemany + ONE commit
        (the ingest path, so a device-supplied window doesn't do a synchronous commit
        per event on the asyncio loop). INSERT OR IGNORE + the same per-session prune."""
        if not rows:
            return
        self.db.executemany(
            "INSERT OR IGNORE INTO events"
            "(tenant_id,session_key,event_id,kind,data) VALUES(?,?,?,?,?)",
            [(tenant_id, session_key, eid, kind, self._encode(data))
             for (eid, kind, data) in rows])
        self._prune(tenant_id, session_key)
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
