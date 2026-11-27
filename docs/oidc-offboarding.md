# OIDC offboarding

Configure your IdP or access management system to send a revocation event when
it removes a subject from all groups that grant access to nebula-mesh, and no
other policy still grants access. Account deactivation also qualifies.

1. Generate a separate random key for this installation with
   `openssl rand -hex 32`. Set the result as
   `NEBULA_MGMT_OIDC_OFFBOARDING_KEY` in the management server's environment.
   Configure the sender to use the same key. Both sides decode it from hex into
   32 bytes.
2. Send `POST /ui/oidc/offboard` over HTTPS with
   `Content-Type: application/json`. If you terminate TLS at a local reverse
   proxy, configure `trusted_secret_ingress_proxy` and forward the original
   HTTPS scheme as described in `configs/server.example.yml`.
3. Compute HMAC-SHA-256 over the exact HTTP request body. Set
   `X-Nebula-Offboarding-Signature` to `sha256=` followed by the hex digest.

The body has these fields.

| Field | Value |
| --- | --- |
| `event_id` | A unique identifier of up to 128 bytes. Keep it stable on retries. |
| `issuer` | The configured `oidc.issuer`, exactly as written. |
| `audience` | The configured `oidc.client_id`. |
| `subject` | The user's OIDC `sub` for this application, up to 255 bytes. |
| `issued_at` | Unix timestamp in seconds for the original event. Keep it stable on retries. |

The server accepts bodies up to 4096 bytes and events younger than five
minutes, with up to 30 seconds of future clock skew. A valid event returns
`204` for a successful revocation, a repeat delivery, or a subject with no
active matching operator. Retry a temporary server error using the original
event. If the event expires before delivery, verify the subject's current
entitlement before issuing a new event.

Revocation disables the linked OIDC operator, invalidates its browser
sessions, and revokes its API keys. An administrator can re-enable the local
operator after the IdP restores access. Previously revoked credentials stay
revoked. The audit log records the operator ID and whether revocation came
from the webhook or a callback.
