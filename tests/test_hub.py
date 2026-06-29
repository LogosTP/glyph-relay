# SPDX-License-Identifier: Elastic-2.0
import asyncio
import unittest

from glyph_relay.hub import format_sse_event, Hub


class FormatSSETest(unittest.TestCase):
    def test_frame_has_event_id_and_compact_json(self):
        frame = format_sse_event(2, "output", {"text": "hi", "prompt": False})
        self.assertEqual(
            frame,
            'event: output\nid: 2\ndata: {"text":"hi","prompt":false}\n\n',
        )

    def test_unicode_is_not_escaped(self):
        frame = format_sse_event(7, "output", {"text": "café"})
        self.assertIn('data: {"text":"café"}', frame)


class HubBufferTest(unittest.TestCase):
    def test_publish_assigns_monotonic_ids_from_one(self):
        hub = Hub(capacity=10)
        self.assertEqual(hub.publish("output", {"text": "a"}), 1)
        self.assertEqual(hub.publish("output", {"text": "b"}), 2)

    def test_backlog_returns_all_then_filters_by_since_id(self):
        hub = Hub(capacity=10)
        hub.publish("output", {"text": "a"})   # id 1
        hub.publish("output", {"text": "b"})   # id 2
        self.assertEqual([e[0] for e in hub.backlog()], [1, 2])
        self.assertEqual([e[0] for e in hub.backlog(since_id=1)], [2])

    def test_ring_buffer_evicts_oldest_past_capacity(self):
        hub = Hub(capacity=2)
        for ch in "abc":
            hub.publish("output", {"text": ch})  # ids 1,2,3
        ids = [e[0] for e in hub.backlog()]
        self.assertEqual(ids, [2, 3])  # id 1 evicted


class HubFanOutTest(unittest.IsolatedAsyncioTestCase):
    async def test_subscriber_receives_live_events(self):
        hub = Hub(capacity=10)
        q = hub.subscribe()
        hub.publish("status", {"state": "connected"})
        event = await asyncio.wait_for(q.get(), 1.0)
        self.assertEqual(event[1:], ("status", {"state": "connected"}))

    async def test_unsubscribe_stops_delivery(self):
        hub = Hub(capacity=10)
        q = hub.subscribe()
        hub.unsubscribe(q)
        hub.publish("status", {"state": "connected"})
        self.assertTrue(q.empty())

    async def test_subscriber_queue_is_bounded_drops_oldest(self):
        # A stalled subscriber (never drains its queue) must not grow without
        # bound; publish evicts the oldest so the queue stays at queue_maxsize.
        hub = Hub(capacity=100, queue_maxsize=3)
        q = hub.subscribe()
        for i in range(10):
            hub.publish("output", {"text": str(i)})
        self.assertEqual(q.qsize(), 3)
        ids = []
        while not q.empty():
            ids.append(q.get_nowait()[0])
        self.assertEqual(ids, [8, 9, 10])  # only the newest 3 survive


if __name__ == "__main__":
    unittest.main()
