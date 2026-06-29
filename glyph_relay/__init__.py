# SPDX-License-Identifier: Elastic-2.0
"""Glyph relay: the source-available, multi-tenant MUD relay (SSE down / POST up).

One codebase, two modes: self-host (single MUD target, RAM-only history, open or
per-user enrollment) and hosted (per-tenant broker-token auth, per-server target,
durable history, admin revoke/purge). See ``config.build_relay`` for mode wiring.
"""
from . import relay, sessions, hub  # noqa: F401
