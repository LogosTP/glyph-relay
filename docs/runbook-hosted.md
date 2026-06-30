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
| `INGEST_RATE` / `INGEST_WINDOW` | no | per-tenant `/ingest` rate limit (default 60 reqs / 60 s; `0` disables) |
| `HISTORY_MAX_ROWS_PER_SESSION` | no | durable-history ring bound per (tenant, session); default 20000 |

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

## Push-trigger pipeline

The relay turns live MUD events into APNs pushes **without** holding any push tokens,
consent state, or per-user keywords — those stay in the private `glyph-hosted` store.
The relay does only a coarse, synchronous classification (`glyph_relay/push.py`,
spec §4.2.1) and a best-effort server-to-server notify POST to the co-located hosted
sender. Constructed only when **both** `RELAY_NOTIFY_URL` and `RELAY_NOTIFY_SECRET`
are set; unset ⇒ no notifier ⇒ hosted-without-push is byte-for-byte unchanged.

**The hop.** On each persisted `Hub.publish`, `PushNotifier` classifies the event
into a coarse `category` (`disconnect` / `tell` / `channel` / `highlight`) with a
bounded ≤256-char snippet, applies a per-(tenant, session) sliding-window cap
(`RELAY_NOTIFY_RATE`/`RELAY_NOTIFY_WINDOW`, default 120/60s), and fire-and-forgets a
plain HTTP/1.1 POST to `RELAY_NOTIFY_URL`. The POST carries
`Content-Type: application/json` and `X-Relay-Notify: <RELAY_NOTIFY_SECRET>`; the
hosted sender holds the token registry + consent + keyword match and performs the
actual APNs send. The POST **never raises** and **never logs** the secret or the
event text — a dead/refusing hosted sender must not break relay event delivery.

```
   MUD ──tn/tls──▶ glyph-relay ──SSE/POST──▶ phone client
                       │
                       │ classify + rate-limit (loopback only)
                       ▼
   127.0.0.1:8080  glyph-hosted  POST /v1/push/notify  (X-Relay-Notify: <secret>)
                       │ consent + keyword + token registry
                       ▼
                     APNs ──▶ device
```

**Config.** Point `RELAY_NOTIFY_URL` at the co-located hosted sender on loopback:

```
RELAY_NOTIFY_URL=http://127.0.0.1:8080/v1/push/notify
RELAY_NOTIFY_SECRET=<env-only; MUST byte-match glyph-hosted's notify secret>
```

`RELAY_NOTIFY_SECRET` is a **secret, env-only** value (never a CLI flag). It must
byte-match the value `glyph-hosted` checks on `POST /v1/push/notify`; a mismatch
makes every notify a silent 401 (the relay swallows it — no push, no error). Treat
it like `SHARED_HMAC_KEY`: rotate both sides together.

### Loopback / firewall posture

- **Notify hop stays on loopback.** `glyph-relay` and `glyph-hosted` are co-located;
  the notify POST goes 127.0.0.1 → 127.0.0.1 and must **never** leave the host. Do
  not route `RELAY_NOTIFY_URL` through the tunnel or a public address — the shared
  notify secret is the only auth on that endpoint.
- **`/admin/*` stays on loopback** (see "Ingress + admin firewalling" above): the
  cloudflared template (`ops/cloudflared-relay.yml`) returns 404 for `/admin/*` on
  the public hostname; the backend reaches admin + notify over the private path.
- **`glyph-hosted` binds loopback too.** Its `POST /v1/push/notify` (8080) accepts
  only the relay's loopback connection with a valid `X-Relay-Notify`; it is never
  fronted by the tunnel. Outbound APNs (443) is the only public egress it needs.
- The relay's own bind is `127.0.0.1:8765` (`ops/glyph-relay.service`); confirm with
  `ss -ltnp 'sport = :8765'` that it is not on a routable interface.

### Deploy checklist

1. Install `glyph-relay` to `/opt/glyph-relay`; install
   `ops/glyph-relay.service` → `/etc/systemd/system/`.
2. Write `/etc/glyph-relay/relay.env` from `.env.example` (root-owned, `chmod 0600`):
   set `RELAY_MODE=hosted`, `SHARED_HMAC_KID/KEY`, `RELAY_ADMIN_SECRET`,
   `HISTORY_DB=/var/lib/glyph-relay/history.db`, the target allowlist, and the
   `RELAY_NOTIFY_URL`/`RELAY_NOTIFY_SECRET` pair.
3. Put `HISTORY_DB` on an encrypted volume (`docs/privacy-hosted.md`).
4. Deploy `glyph-hosted` co-located, bound loopback `127.0.0.1:8080`, with the SAME
   `RELAY_NOTIFY_SECRET` and its APNs `.p8` (env/secret-store only, never committed).
5. Install `ops/cloudflared-relay.yml` → `/etc/cloudflared/config.yml`; fill tunnel
   UUID + credentials + `relay.<domain>`; verify `/admin/*` returns 404 publicly.
6. `systemctl enable --now glyph-relay`; check `GET https://relay.<domain>/health`.
7. Verify the notify hop end-to-end (a test `tell` ⇒ device push) with a real device
   token in `glyph-hosted`'s registry.

### Blocking infra (filed, not performed here)

The host provisioning, encrypted-volume mount, tunnel DNS, and APNs portal steps are
tracked as homelab infra issues — referenced, not executed, by this repo:

- **homelab#274** — provision the relay host + encrypted `HISTORY_DB` volume + the
  `glyph-relay` systemd unit and `/etc/glyph-relay/relay.env`.
- **homelab#275** — cloudflared tunnel + `relay.<domain>` DNS; assert `/admin/*` and
  the notify hop are loopback-only (not publicly routable).
- **homelab#276** — Apple Developer portal: APNs `.p8` auth key + bundle/key ids for
  `glyph-hosted`; deliver to the secret store (never the repo).
