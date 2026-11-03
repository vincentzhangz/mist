# Auth

Email + password login with HS256 JWTs. Verified against
`crates/mist-api/src/auth.rs` and the `require_auth` middleware in
`crates/mist-api/src/middleware.rs`.

## Login

`POST /api/auth/login` with `{ "email", "password" }`:

- looks up the user in the `users` table (`migrations/002_auth.sql`),
- verifies the argon2 hash (in `spawn_blocking`, so hashing never stalls
  the runtime),
- returns `{ "token", "email" }` on success, `401 { "error" }` otherwise.
  Unknown users pay one dummy argon2 verification so login timing doesn't
  reveal which emails exist.

Tokens are HS256, `sub` = email, 24h expiry.

## Which routes need the token

| Endpoint | Auth |
|---|---|
| `GET /healthz` | none |
| `GET /metrics` | none — public for in-cluster Prometheus scraping |
| `POST /api/auth/login` | none |
| `POST /api/ingest` | `Authorization: Bearer <INGEST_TOKEN>` when a token is provisioned; open otherwise (dev only, loud warning at startup). Moves to the client-cert-gated `:3001` listener when `CLIENT_CA_CERT` is set (see mTLS ingest below) |
| `GET /api/flows`, `GET /api/alerts`, `GET /api/alerts/{id}`, `POST /api/alerts/{id}/resolve` | `Authorization: Bearer <token>` |
| `GET /api/ws` | `?token=<token>` query param (browsers can't set headers on upgrade) |
| `/`, `/login`, `/alerts`, assets | none — the dashboard shell is public; it redirects to login without a token |

Anything else under `/api/*` returns a JSON 404 (never the SPA shell).

## mTLS ingest (opt-in)

With `TLS_CERT` + `TLS_KEY` the main listener serves HTTPS; adding
`CLIENT_CA_CERT` opens a second, ingest-only HTTPS listener on
`INGEST_BIND_ADDR` (default `0.0.0.0:3001`) that requires a client
certificate chained to that CA. Verification happens inside the TLS
handshake, so peers without a valid client cert never reach a handler,
and `/api/ingest` leaves the main port so it cannot bypass the gate.
Agents present `--tls-cert` + `--tls-key` (`MIST_TLS_CERT` /
`MIST_TLS_KEY`), trust the server CA via `--tls-ca-cert`, and keep
sending the ingest credential alongside the certificate (defense in
depth). Half-mounted identities are startup errors on both ends, never
silent downgrades.

Verification is membership-only: any client chaining to the CA is
accepted; cert subjects are not mapped to node names yet. Rotate by
reissuing and restarting (no hot reload). Wiring is Secret-driven: the
chart takes `api.tlsSecretName` (server identity + client CA) and
`agent.clientCertSecretName` (agent identity + server CA); the operator
mounts the agent side from
`TrafficMonitor.spec.clientCertSecretName`.

## Configuration

| Var | Effect |
|---|---|
| `JWT_SECRET` | HS256 signing key. **Required** — the API refuses to start without it (fail closed). Set a random value (`openssl rand -hex 32`); local runs just export any value. |
| `ADMIN_EMAIL` + `ADMIN_PASSWORD` | Bootstrap admin: hashed (argon2) and upserted at every startup. If either is unset, nothing is seeded and login fails closed (401 for everyone). |
| `INGEST_TOKEN` + `INGEST_TOKENS` | Accepted agent credentials (single + comma-separated list). When any is set, `/api/ingest` requires one as `Bearer`; when unset, ingest stays open with a loud warning. Agents send `--api-token` / `MIST_API_TOKEN` (the operator injects it from the monitor's `apiTokenSecretName`). Rotate by appending the new token, rolling agents, removing the old. Provision high-entropy values anywhere shared. |
| `TLS_CERT` + `TLS_KEY` | PEM server cert + key paths. Both set serves HTTPS on the main port; exactly one set is a startup error. |
| `CLIENT_CA_CERT` + `INGEST_BIND_ADDR` | PEM client-CA path enabling the ingest-only mTLS listener (default `0.0.0.0:3001`); requires the pair above, and `/api/ingest` leaves the main port. |
| `DATABASE_URL` | With Postgres the users table persists (migration `002_auth.sql`); without it the in-memory store still accepts the seeded admin, but users vanish on restart. |

In-cluster all four come from one Secret: `deploy/api-auth-secret.example`
is the template (copy to the gitignored `api-auth-secret.yaml`), and the
chart renders it from `api.jwtSecret` / `api.adminEmail` /
`api.adminPassword` / `api.ingestToken`.

## Consequences

- Keep `mist-api` cluster-local unless `INGEST_TOKEN` is provisioned:
  without it anyone who can reach the API can inject fake flow batches
  via `/api/ingest`.
- The operator webhook (`POST /alerts` on `:8081`) is unauthenticated by
  design and must stay cluster-internal (no external Service/ingress in
  `deploy/` or the chart).
- The `mist-dev-password` Postgres credential in `deploy/postgres.yaml`
  (and the chart default) is dev-only; override it anywhere shared.

## Roadmap (not implemented)

Ingest accepts a token set (rotation-friendly), but per-agent tokens are
provisioned manually and there is no per-token identity in audit trails.
Login is rate-limited per IP (10/min, `429 + Retry-After`); defense in
depth still favors a rate-limiting ingress in front of any
internet-facing deployment. The API serves plain HTTP unless `TLS_CERT`
+ `TLS_KEY` are set — terminate TLS at the ingress or provision those in
any environment where the pod network isn't trusted. Client certificates
prove PKI membership only; mapping cert subjects to node names (per-node
agent identity) is future work — it needs a manual rustls accept loop
(axum-server exposes no peer-cert API) plus per-node certificate issuance,
which no component provisions today.
