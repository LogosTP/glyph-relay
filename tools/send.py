#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0
"""Append a single command line to the client's command file.

Usage: python3 tools/send.py [--file var/commands.in] "command text"
"""
import argparse


def append_command(path, command):
    with open(path, "a", encoding="utf-8") as f:
        f.write(command.rstrip("\n") + "\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Send a command to the MUD client.")
    parser.add_argument("--file", default="var/commands.in")
    parser.add_argument("command")
    args = parser.parse_args(argv)
    append_command(args.file, args.command)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
