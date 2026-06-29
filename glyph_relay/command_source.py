# SPDX-License-Identifier: Elastic-2.0
"""Tail an append-only command file; yield only lines added after startup."""
import asyncio
import os


class CommandSource:
    def __init__(self, path, poll=0.2):
        self.path = path
        self.poll = poll
        open(self.path, "a", encoding="utf-8").close()
        self._start = os.path.getsize(self.path)

    async def commands(self):
        with open(self.path, "r", encoding="utf-8") as f:
            f.seek(self._start)
            while True:
                line = f.readline()
                if line:
                    line = line.rstrip("\n")
                    if line:
                        yield line
                else:
                    await asyncio.sleep(self.poll)
