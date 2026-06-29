# SPDX-License-Identifier: Elastic-2.0
import unittest

from glyph_relay.connection import Connection


class _FakeReader:
    def __init__(self, chunks):
        self._chunks = list(chunks)

    async def read(self, _n):
        return self._chunks.pop(0) if self._chunks else b""


class ConnectionDecodeTest(unittest.IsolatedAsyncioTestCase):
    async def test_multibyte_utf8_split_across_reads_is_reassembled(self):
        # 'café\r\n' with the 2-byte 'é' (\xc3\xa9) split across two reads.
        conn = Connection("h", 0, use_tls=False)
        conn._reader = _FakeReader([b"caf\xc3", b"\xa9\r\n"])
        conn._writer = None   # no negotiation bytes -> writer is never touched

        out = []
        async for text, _events in conn.receive():
            out.append(text)
        self.assertEqual("".join(out), "café\r\n")


if __name__ == "__main__":
    unittest.main()
