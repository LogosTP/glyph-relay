# Hosted relay — privacy & data handling

This applies only to the **hosted** mode of `glyph-relay`. A self-hosted relay
(default) stores nothing durably and is operated by the user themselves; nothing
below applies to it.

## What the hosted relay stores

To deliver always-on sessions and catch-up beyond the in-RAM window, the hosted
relay keeps a **durable, server-side copy of each session's MUD output stream** in a
SQLite `events` table (`history.py` `HistoryStore`), keyed by `(tenant_id,
session_key, event_id)`:

- **MUD session content** — the text the MUD sent you, plus your own echoed
  commands, as a monotonic event stream. This is what powers reconnect/catch-up and
  the per-tenant history.
- **Session metadata** — host, port, TLS flag, account email, character name,
  created-at, and the latest event id (surfaced by `GET /sessions`).

## What it never stores

- **Passwords / credentials.** The durable sink sits at/after `Hub.publish`, which
  only ever sees **post-`_scrub`** payloads (secrets already masked as `********`).
  Raw MUD passwords are never written to history. A sink wired upstream of `_scrub`
  would be a defect — it is guarded by test.
- **Broker tokens / bearer tokens / admin secrets** are never logged.
- **No downloaded logic / no on-device code** — per-server behaviour is data-driven.

## Retention, export, and erasure

- **Retention:** session history is retained while the tenant's subscription is
  active, plus a short grace window after unsubscribe, then purged.
- **Export:** `HistoryStore.export(tenant)` returns the tenant's full event history
  (admin/operator tooling; tenant-scoped).
- **Erasure:** `POST /admin/purge {tenant_id}` (and `HistoryStore.delete(tenant)`)
  deletes **all** of that tenant's durable history. `POST /admin/revoke {tenant_id}`
  additionally denylists the tenant and tears down its live sessions within one
  reaper cycle. Both are tenant-scoped — one tenant's data is never readable or
  erasable by another.

## Encryption at rest

Encryption at rest is **operational**, not in code: deploy the SQLite database on an
encrypted volume (FileVault / LUKS / cloud-provider volume encryption). This keeps
the relay stdlib-only (no crypto dependency) while protecting the at-rest copy.

## Tenant isolation

Every history read/write filters on `tenant_id`; `GET /sessions`, ingest, and the
admin routes are scoped strictly to the caller's own tenant — never global. The
per-server target is bounded by the SSRF allowlist (`targets.is_allowed_target`) so
a user-supplied target cannot reach the relay's own network.
