# Reverse-proxy snippets

Working configurations for the three reverse proxies operators reach
for most often when fronting `nebula-mgmt` with TLS. Each file is
opinionated, commented, and copy-pasteable — pick one, change the
hostname, reload the proxy.

| Path | Use when |
|---|---|
| [`nginx/nebula-mgmt.conf`](nginx/nebula-mgmt.conf) | nginx ≥ 1.18; certificates managed by certbot. |
| [`caddy/Caddyfile`](caddy/Caddyfile) | Caddy 2.x; automatic Let's Encrypt with zero config. |
| [`traefik/dynamic.yml`](traefik/dynamic.yml) | Traefik v3 with the file provider. |

All three:

- terminate TLS on `:443` and proxy plain HTTP to `127.0.0.1:8080`;
- preserve the real client IP via `X-Forwarded-For` (works with
  `rate_limit.trust_proxy_header: true` in `server.yml`);
- disable buffering on `/ui/events` so the Server-Sent Events feed
  (issue #43) reaches the browser in real time;
- set HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  and `Referrer-Policy: no-referrer`.

The agent endpoints (`/api/v1/enroll`, `/api/v1/agent/updates`) carry
their own bearer / token authentication — do **not** stack HTTP basic
auth in the proxy on top of them.

## Optional: mTLS on the UI only (issue #69)

Each of the three snippets ships a commented-out block that gates the
**UI surface only** behind a client certificate, leaving `/api/`,
`/healthz`, `/readyz`, `/metrics`, and `/debug/` reachable without one.
Why split the surfaces:

- Browsers can present a client cert (per-operator, issued from your
  internal PKI), giving an extra factor on top of the password / 2FA.
- Agents authenticate with an enrollment token or their host cert at
  the application layer — they have no operator-cert chain to present.
- Prometheus / monitoring rarely scrapes through mTLS, and the ops
  endpoints have no secrets in their responses.

In-binary mTLS would require a second `net.Listener` per route, which
expands the operational surface — keeping `crypto/tls.ClientAuth` in
the reverse proxy is the cleaner lever. To enable on your setup,
uncomment the marked block in the file for your proxy and supply the
operator-CA bundle (the CA that signs operator client certs).
