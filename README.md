# glyph-relay

The source-available, multi-tenant evolution of the Glyph relay — an SSE-down /
POST-up bridge that lets phone clients attach to a live MUD session. Python 3.8+,
**standard library only** (no pip dependencies, ever).

> "Glyph" is a trademark of the copyright holder. See `NOTICE` — forks must
> rename. Licensed under the **Elastic License 2.0** (`LICENSE`): you may not
> offer this software to third parties as a hosted or managed service.

## Two modes, one codebase

- **Self-host** — one statically-configured MUD target, RAM-only history, and an
  open or per-user-enrollment (`X-Relay-Enroll: <id>.<secret>`) gate. Behaviour is
  unchanged from the single-tenant Glyph client relay.
- **Hosted** — per-tenant **broker-token** auth (HMAC, `X-Relay-Enroll`), a
  per-request **MUD target** (one relay serves many MUDs) bounded by an SSRF
  allowlist, **per-tenant** session quotas + isolation, **durable** SQLite session
  history (export/delete), and admin `POST /admin/revoke|purge` (`X-Relay-Admin`).

Mode is selected by `glyph_relay.config.build_relay(mode, env)`:

```python
from glyph_relay.config import build_relay
relay = build_relay("selfhost", {"GLYPH_ENROLL_SECRET": "..."})   # or "hosted"
```

## HTTP surface

| Method | Route                              | Auth                | Notes |
|--------|------------------------------------|---------------------|-------|
| GET    | `/health`                          | none                | liveness |
| POST   | `/session`                         | enroll/broker       | mint a session token; optional `target` |
| GET    | `/sessions`                        | bearer or enroll    | the caller's own live sessions (tenant-scoped) |
| GET    | `/events`                          | bearer              | SSE stream (backlog then live) |
| POST   | `/command`                         | bearer              | submit one command line |
| POST   | `/sessions/{sessionKey}/ingest`    | bearer/tenant       | slot a device history window into the stream |
| POST   | `/logout`                          | bearer              | tear down the session |
| POST   | `/admin/revoke`                    | `X-Relay-Admin`     | denylist a tenant + reap its sessions |
| POST   | `/admin/purge`                     | `X-Relay-Admin`     | delete a tenant's durable history |

The relay binds `127.0.0.1` only; a TLS tunnel provides public reach.

## Run

```sh
# Self-host (open):
python3 -m glyph_relay --host 127.0.0.1 --port 8765 \
    --mud-host mud.example.com --mud-port 4000

# Per-user enrollment (self-host):
python3 -m glyph_relay.enrollment add --label "my phone"   # prints id.secret once
python3 -m glyph_relay --relay-enroll-db var/enrollments.db ...
```

## Test

No build step (stdlib only). Run the suite:

```sh
python3 -m unittest discover -s tests -v
```

## Repo layout

- `glyph_relay/` — the relay package. `telnet.py`/`negotiator.py` are the sans-IO
  core (no I/O); `relay.py`/`sessions.py`/`hub.py` are the asyncio server;
  `auth.py`/`targets.py`/`history.py`/`config.py` are the multi-tenant additions;
  `login.py` is the MUD login state machine; `enrollment.py` is the per-user
  registry + CLI.
- `stub/` — a local single-room MUD used by the tests.
- `tests/` — `unittest` suites.
- `docs/` — privacy + ops runbook for the hosted mode.

## Contributing

By contributing you agree to the `CLA.md`; sign off every commit (`git commit -s`).
