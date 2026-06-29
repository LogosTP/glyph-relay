# SPDX-License-Identifier: Elastic-2.0
import importlib.util
import os
import tempfile
import unittest

_SPEC = importlib.util.spec_from_file_location(
    "send_tool", os.path.join(os.path.dirname(__file__), "..", "tools", "send.py")
)
send_tool = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(send_tool)


class SendTest(unittest.TestCase):
    def test_append_command_adds_newline_terminated_line(self):
        path = os.path.join(tempfile.mkdtemp(), "commands.in")
        send_tool.append_command(path, "look")
        send_tool.append_command(path, "say hi")
        with open(path, encoding="utf-8") as f:
            self.assertEqual(f.read(), "look\nsay hi\n")


if __name__ == "__main__":
    unittest.main()
