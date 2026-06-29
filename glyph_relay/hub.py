# SPDX-License-Identifier: Elastic-2.0
"""Fan-out hub + bounded ring buffer feeding the relay's SSE stream.

Pure pieces (frame formatting, ring buffer, backlog) plus an asyncio fan-out to
live subscribers. No HTTP here -- the Relay (relay.py) writes these frames.
"""
import asyncio
import json


def format_sse_event(event_id, kind, data):
    """Serialize one Server-Sent Event frame (UTF-8, compact JSON)."""
    payload = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    return "event: {}\nid: {}\ndata: {}\n\n".format(kind, event_id, payload)


class Hub:
    """Bounded ring buffer of (id, kind, data) events with live fan-out."""

    def __init__(self, capacity=500, queue_maxsize=2000):
        self.capacity = capacity
        # Per-subscriber live queue bound. A stalled client (blocked on drain)
        # stops consuming; without a bound its queue would grow without limit and
        # exhaust the daemon's memory. We drop the oldest queued event instead.
        self.queue_maxsize = queue_maxsize
        self._buf = []          # [(id, kind, data)], oldest first
        self._next_id = 1
        self._subs = set()      # {asyncio.Queue}

    def publish(self, kind, data):
        event = (self._next_id, kind, data)
        self._next_id += 1
        self._buf.append(event)
        if len(self._buf) > self.capacity:
            self._buf = self._buf[-self.capacity:]
        for q in self._subs:
            if q.maxsize and q.full():
                try:
                    q.get_nowait()  # evict oldest for a stalled subscriber
                except asyncio.QueueEmpty:
                    pass
            q.put_nowait(event)
        return event[0]

    def backlog(self, since_id=None):
        if since_id is None:
            return list(self._buf)
        return [e for e in self._buf if e[0] > since_id]

    def latest_status(self):
        """The most recent 'status' event still in the buffer, or None. The relay
        sends this to every newly-attached /events subscriber so it learns the
        current connection state immediately -- even when its Last-Event-ID (or a
        daemon restart) skipped past the status event, which otherwise leaves a
        reconnecting client's input stuck disabled."""
        for event in reversed(self._buf):
            if event[1] == "status":
                return event
        return None

    def subscribe(self):
        q = asyncio.Queue(maxsize=self.queue_maxsize)
        self._subs.add(q)
        return q

    def unsubscribe(self, q):
        self._subs.discard(q)
