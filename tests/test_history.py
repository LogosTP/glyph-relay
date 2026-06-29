# SPDX-License-Identifier: Elastic-2.0
"""Durable per-tenant history (spec §3.1): HistoryStore + Hub durable sink +
event-id continuity across restarts."""
import unittest

from glyph_relay.history import HistoryStore
from glyph_relay.hub import Hub


class HistoryStoreTests(unittest.TestCase):
    def setUp(self):
        self.h = HistoryStore(":memory:")

    def test_append_and_backlog(self):
        self.h.append("A", "s1", 1, "output", {"text": "hello"})
        self.h.append("A", "s1", 2, "output", {"text": "world"})
        rows = self.h.backlog("A", "s1")
        self.assertEqual([r[0] for r in rows], [1, 2])
        self.assertEqual(rows[1][2], {"text": "world"})

    def test_backlog_since(self):
        for i in (1, 2, 3):
            self.h.append("A", "s1", i, "output", {"i": i})
        self.assertEqual([r[0] for r in self.h.backlog("A", "s1", since_id=1)], [2, 3])

    def test_tenant_isolation(self):
        self.h.append("A", "s1", 1, "output", {"x": 1})
        self.h.append("B", "s1", 1, "output", {"x": 2})
        self.assertEqual(len(self.h.backlog("A", "s1")), 1)
        self.assertEqual(self.h.export("A"),
                         [{"session_key": "s1", "event_id": 1, "kind": "output", "data": {"x": 1}}])

    def test_session_isolation_within_tenant(self):
        self.h.append("A", "s1", 1, "output", {"x": 1})
        self.h.append("A", "s2", 1, "output", {"x": 2})
        self.assertEqual(self.h.backlog("A", "s1")[0][2], {"x": 1})
        self.assertEqual(self.h.backlog("A", "s2")[0][2], {"x": 2})

    def test_delete_purges_only_that_tenant(self):
        self.h.append("A", "s1", 1, "output", {"x": 1})
        self.h.append("B", "s1", 1, "output", {"x": 2})
        self.assertEqual(self.h.delete("A"), 1)
        self.assertEqual(self.h.backlog("A", "s1"), [])
        self.assertEqual(len(self.h.backlog("B", "s1")), 1)

    def test_max_event_id(self):
        self.assertIsNone(self.h.max_event_id("A", "s1"))
        self.h.append("A", "s1", 7, "output", {"x": 1})
        self.h.append("A", "s1", 9, "output", {"x": 2})
        self.assertEqual(self.h.max_event_id("A", "s1"), 9)
        # Scoped: another session's ids don't bleed in.
        self.assertIsNone(self.h.max_event_id("A", "s2"))

    def test_append_is_idempotent_on_duplicate_id(self):
        # INSERT OR IGNORE: a device cannot overwrite an existing relay id.
        self.h.append("A", "s1", 1, "output", {"text": "real"})
        self.h.append("A", "s1", 1, "output", {"text": "forged"})
        rows = self.h.backlog("A", "s1")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][2], {"text": "real"})


class HubSinkTests(unittest.TestCase):
    def test_publish_writes_through_to_history(self):
        h = HistoryStore(":memory:")
        hub = Hub(sink=h, tenant_id="A", session_key="s1")
        hub.publish("output", {"text": "hi"})
        hub.publish("output", {"text": "there"})
        rows = h.backlog("A", "s1")
        self.assertEqual([r[2]["text"] for r in rows], ["hi", "there"])

    def test_no_sink_is_ram_only(self):
        hub = Hub()  # self-host default: no durable writes, no crash
        self.assertEqual(hub.publish("output", {"text": "x"}), 1)
        self.assertEqual(len(hub.backlog()), 1)

    def test_event_id_continuity_seeds_from_persisted_max(self):
        # §3.1: a Hub with a durable sink that already holds events seeds _next_id from
        # MAX(persisted)+1 so ids don't rewind/collide after a relay restart.
        h = HistoryStore(":memory:")
        h.append("A", "s1", 5, "output", {"text": "old"})
        hub = Hub(sink=h, tenant_id="A", session_key="s1")
        self.assertEqual(hub.publish("output", {"text": "new"}), 6)  # not 1

    def test_fresh_sink_starts_at_one(self):
        h = HistoryStore(":memory:")
        hub = Hub(sink=h, tenant_id="A", session_key="s1")
        self.assertEqual(hub.publish("output", {"text": "new"}), 1)


class AppendManyTests(unittest.TestCase):
    """Batched durable write for the ingest path (Finding 2)."""

    def test_append_many_single_batch_persists_monotonic(self):
        h = HistoryStore(":memory:")
        rows = [(1, "output", {"i": 1}), (2, "output", {"i": 2}), (3, "output", {"i": 3})]
        h.append_many("A", "s1", rows)
        got = h.backlog("A", "s1")
        self.assertEqual([r[0] for r in got], [1, 2, 3])
        self.assertEqual([r[2]["i"] for r in got], [1, 2, 3])

    def test_append_many_is_insert_or_ignore(self):
        # A duplicate id in the batch cannot overwrite an existing relay-assigned row.
        h = HistoryStore(":memory:")
        h.append("A", "s1", 1, "output", {"text": "real"})
        h.append_many("A", "s1", [(1, "output", {"text": "forged"}),
                                  (2, "output", {"text": "new"})])
        got = h.backlog("A", "s1")
        self.assertEqual(got[0][2], {"text": "real"})
        self.assertEqual(got[1][2], {"text": "new"})

    def test_append_many_empty_is_noop(self):
        h = HistoryStore(":memory:")
        h.append_many("A", "s1", [])
        self.assertEqual(h.backlog("A", "s1"), [])


class RetentionCapTests(unittest.TestCase):
    """Per-(tenant, session) durable-history bound (Finding 1b): append cannot grow
    without limit; the oldest rows are pruned (ring)."""

    def test_append_prunes_oldest_beyond_cap(self):
        h = HistoryStore(":memory:", max_rows_per_session=5)
        for i in range(1, 11):           # ids 1..10, cap 5
            h.append("A", "s1", i, "output", {"i": i})
        got = h.backlog("A", "s1")
        self.assertEqual([r[0] for r in got], [6, 7, 8, 9, 10])  # only newest 5

    def test_append_many_prunes_oldest_beyond_cap(self):
        h = HistoryStore(":memory:", max_rows_per_session=4)
        h.append_many("A", "s1", [(i, "output", {"i": i}) for i in range(1, 11)])
        got = h.backlog("A", "s1")
        self.assertEqual([r[0] for r in got], [7, 8, 9, 10])     # only newest 4

    def test_cap_is_per_session_not_global(self):
        h = HistoryStore(":memory:", max_rows_per_session=3)
        for i in range(1, 6):
            h.append("A", "s1", i, "output", {"i": i})
            h.append("A", "s2", i, "output", {"i": i})
        self.assertEqual(len(h.backlog("A", "s1")), 3)
        self.assertEqual(len(h.backlog("A", "s2")), 3)

    def test_no_cap_is_unbounded(self):
        h = HistoryStore(":memory:")                 # default: no cap
        for i in range(1, 21):
            h.append("A", "s1", i, "output", {"i": i})
        self.assertEqual(len(h.backlog("A", "s1")), 20)


class PragmaTests(unittest.TestCase):
    """WAL + synchronous=NORMAL so per-row commits don't block the loop (Finding 2a)."""

    def test_wal_and_synchronous_normal_on_file_db(self):
        import os
        import tempfile
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        h = HistoryStore(os.path.join(d.name, "h.db"))
        self.addCleanup(h.close)
        mode = h.db.execute("PRAGMA journal_mode").fetchone()[0]
        self.assertEqual(mode.lower(), "wal")
        # synchronous: 1 == NORMAL
        self.assertEqual(h.db.execute("PRAGMA synchronous").fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
