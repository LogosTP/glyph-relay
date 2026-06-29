# Hosted relay — operations runbook

Operating `glyph-relay` in **hosted** mode (per-tenant broker-token auth, durable
history, admin surface). For self-host, just run `python3 -m glyph_relay` with a MUD
target; none of the hosted-only setup below is needed.

## Environment

Secrets are **environment-only** (never CLI flags, so they don't show in a process
listing). All values are read by `config.build_relay("hosted", env)`.

| Variable | Required | Meaning |
|----------|----------|---------|
| `SHARED_HMAC_KEY` | yes | broker-token signing key (shared with `glyph-hosted` #2). **Secret.** |
| `SHARED_HMAC_KID` | yes | key id (e.g. `v1`); rotate by adding the new kid while keeping the old |
| `RELAY_ADMIN_SECRET` | yes | `X-Relay-Admin` value for revoke/purge. **Secret.** |
| `HISTORY_DB` | yes | path to the durable SQLite db (on an encrypted volume) |
| `RELAY_TARGET_ALLOWLIST` | recommended | host[:port]-per-line file; the public-server directory |
| `RELAY_TARGET_PORTS` | no | tighten the allowed port window, `lo-hi` (e.g. `1024-65535`) |
| `RELAY_HOST` / `RELAY_PORT` | no | bind address (default `127.0.0.1:8765`) |
| `MAX_SESSIONS` / `MAX_PER_TENANT` | no | global / per-tenant session caps (default 200 / 5) |
| `IDLE_TTL` | no | idle-session reap seconds (default 1800) |
| `SESSION_RATE` / `SESSION_WINDOW` | no | POST /session rate limit |

Key rotation: to rotate `SHARED_HMAC_KEY`, the relay's `BrokerTokenAuth` accepts a
**map** of `{kid: key}`. Add the new kid as current while keeping the previous so
tokens minted under either verify during the overlap, then drop the old kid.

## Disk encryption (required)

History at rest is **not** encrypted in code (stdlib-only). Put `HISTORY_DB` on an
encrypted volume (FileVault / LUKS / cloud volume encryption). See
`docs/privacy-hosted.md`.

## Ingress + admin firewalling

- Front the relay with a TLS tunnel (e.g. Cloudflare tunnel) bound to the hosted
  hostname; the relay itself binds `127.0.0.1` only.
- **Do not expose `/admin/*` publicly.** The admin routes are gated by
  `X-Relay-Admin`, but they should additionally be reachable **only** from the
  backend host / localhost — terminate them at the tunnel or a reverse proxy so they
  never traverse the public hostname. The backend (`glyph-hosted`) calls
  `POST /admin/revoke|purge` over the private path on refund/expiry/abuse.
- Enable **edge rate-limiting** on `POST /session` (auth path) as defence-in-depth;
  the relay's own limiter is a backstop.

## Operational endpoints

- `GET /health` — liveness (no auth).
- `POST /session` — mint a session; `X-Relay-Enroll: <broker-token>`; optional
  per-server `target`.
- `GET /sessions` — the caller's own live sessions (#141 re-attach).
- `POST /sessions/{sessionKey}/ingest` — slot a device history window into the stream.
- `POST /admin/revoke {tenant_id}` — denylist + reap a tenant (private path only).
- `POST /admin/purge {tenant_id}` — erase a tenant's durable history (private path only).

## Reaper

`SessionManager.run_reaper` runs every `--reaper-interval` seconds (default 60): it
closes idle sessions (loop clock) and, in self-host #140 deployments, sessions whose
enrollment was revoked/expired (wall clock). In hosted mode, revocation is immediate
at the gate (denylist) plus `POST /admin/revoke` reaps live sessions on demand.
