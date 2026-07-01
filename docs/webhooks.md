# Webhooks

The server can POST lifecycle events to an operator-configured HTTP endpoint so
external systems react to mesh changes without polling — inventory/CMDB sync on
enrollment, SOC alerting on block/revoke, automation on cert rotation. Delivery
is asynchronous (off the request path), signed, and SSRF-guarded.

The machine-readable contract for every event lives in
[`api/openapi.yaml`](../api/openapi.yaml) under `webhooks:`; the contract tests
validate the real emitted payloads against it.

## Enabling

```yaml
# server.yml
webhooks:
  enabled: true
  url: https://hooks.example.com/nebula
  hmac_secret: "<random secret>"        # optional; signs each delivery
  events: [host.enrolled, host.blocked] # optional; empty = all events
  allow_private: false                  # set true only for an intentional internal sink
```

`url` is validated at startup (must be http/https; loopback/private/link-local
targets are rejected unless `allow_private: true`).

The config webhook is a single static target. For multiple endpoints, runtime
management, and per-endpoint delivery status, use **managed subscriptions**
below — both are delivered through the same bus.

## Managed subscriptions

Subscriptions are operator-owned rows managed through the REST API; they need no
config and take effect immediately (no restart). Each is one delivery target
with its own URL, event filter, signing secret, and delivery status.

```
GET    /api/v1/webhook-subscriptions          # list (admin: all; operator: own)
POST   /api/v1/webhook-subscriptions          # create
GET    /api/v1/webhook-subscriptions/{id}     # get
PATCH  /api/v1/webhook-subscriptions/{id}     # update
DELETE /api/v1/webhook-subscriptions/{id}     # delete
```

Create body (all but `url` optional):

```json
{
  "url": "https://hooks.example.com/team-a",
  "events": ["host.enrolled", "cert.expiring"],
  "active": true,
  "allow_private": false,
  "secret": "<hmac secret>"
}
```

- `events` empty/omitted means all events.
- `secret` is **write-only**: it is stored envelope-encrypted under
  `NEBULA_MGMT_MASTER_KEY` (the same scheme as CA keys) and never returned.
  Responses expose only `has_secret`. On update, omit `secret` to keep it, send
  `""` to clear it, or a new value to replace it. A non-empty secret requires
  the master key to be configured.
- `url` is SSRF-validated like the config webhook; `allow_private: true` opts a
  private/loopback target in. Setting `allow_private` requires the admin role —
  a non-admin operator sending it gets `403`.

Each subscription tracks `last_delivery_at`, `last_status` (`ok`/`failed`),
`last_error`, and `consecutive_failures` for observability.

## Events

| Event | Fires when | `data` fields |
|---|---|---|

| Event | Fires when | `data` fields |
|---|---|---|
| `host.enrolled` | a host completes enrollment | `host_id`, `host_name`, `network_id`, `ca_id`, `fingerprint` |
| `host.blocked` | a host is blocked (cert revoked) | `host_id`, `host_name`, `network_id`, `ca_id` |
| `host.unblocked` | a blocked host is unblocked | same as `host.blocked` |
| `host.deleted` | a host is deleted (cert revoked) | same as `host.blocked` |
| `cert.rotated` | a host cert is re-signed in place | host fields + new `fingerprint` |
| `cert.expiring` | a cert approaches expiry without renewal | host fields + `fingerprint`, `not_after`, `seconds_until_expiry` |

`cert.expiring` is produced by the cert-expiry scanner, so it requires
`alerts.enabled: true` (the scanner) in addition to `webhooks.enabled`. The
other events come from the API handlers and need only the webhooks block.

## Delivery format

Every delivery is `POST <url>` with `Content-Type: application/json` and a body:

```json
{
  "id": "evt_2f1c…",
  "type": "host.blocked",
  "created_at": "2026-06-13T12:00:00Z",
  "data": { "host_id": "…", "host_name": "…", "network_id": "…", "ca_id": "…" }
}
```

Headers:

- `X-Nebula-Event` — the event type (also in the body).
- `X-Nebula-Delivery` — the unique event id; use it to deduplicate (delivery is at-least-once).
- `X-Nebula-Signature` — `sha256=<hex>`, the HMAC-SHA256 of the raw body under `hmac_secret` (present only when a secret is set).

## Verifying the signature

Compute `HMAC-SHA256(hmac_secret, raw_request_body)` and compare, in constant
time, against the hex in `X-Nebula-Signature` (after the `sha256=` prefix).
Reject deliveries that do not match.

## Reliability

- **Asynchronous**: events are queued and delivered by a background worker; a
  slow or down receiver never blocks an API request.
- **Retried**: a failed delivery (connection error or HTTP ≥ 400) is retried a
  few times with linear backoff. After the retries are exhausted the event is
  logged and dropped (a durable dead-letter queue is a later phase).
- **Best-effort under load**: if the in-memory queue is full the event is
  dropped with a logged warning rather than stalling the server. Treat webhooks
  as a notification stream, not a system of record — the audit log remains the
  authoritative history.

## Not yet

- A Web UI for managing subscriptions (the REST API exists today).
- `ca.expiring` and other CA-lifecycle events.
- A persistent dead-letter queue and delivery dashboards.
