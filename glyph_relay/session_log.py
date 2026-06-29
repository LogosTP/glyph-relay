# SPDX-License-Identifier: Elastic-2.0
"""Transcript writer: clean (ANSI-stripped) output + source-tagged commands."""
import os
import re

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def strip_ansi(text):
    return _ANSI_RE.sub("", text)


class SessionLog:
    def __init__(self, path, raw_path=None):
        self.path = path
        self.raw_path = raw_path
        self._ensure_parent(path)
        if raw_path:
            self._ensure_parent(raw_path)

    @staticmethod
    def _ensure_parent(path):
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)

    def log_output(self, text):
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(strip_ansi(text))

    def log_command(self, source, cmd):
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(">> ({}) {}\n".format(source, cmd))

    def log_raw(self, direction, data):
        if not self.raw_path:
            return
        with open(self.raw_path, "ab") as f:
            f.write(direction.encode() + b" " + data + b"\n")
