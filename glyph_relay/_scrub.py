# glyph_relay/_scrub.py
# SPDX-License-Identifier: Elastic-2.0
"""Shared security helpers used by both app.py and sessions.py.

Kept in a separate module to avoid the import cycle that would arise if
sessions.py imported from app.py (which itself imports from sessions.py).
"""
import asyncio


def scrub_secrets(secrets, text):
    """Replace each non-empty secret with ``********`` (transcript masking)."""
    for secret in secrets:
        if secret:
            text = text.replace(secret, "********")
    return text


def drain_queue(queue):
    """Discard everything queued (a stale command must never reach a fresh login
    prompt -- on the v1 server a stray line at the password prompt becomes the
    password)."""
    while True:
        try:
            queue.get_nowait()
        except asyncio.QueueEmpty:
            break
