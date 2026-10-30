# Auth

Email + password login with HS256 JWTs. Verified against
`crates/mist-api/src/auth.rs` and the `require_auth` middleware in
`crates/mist-api/src/main.rs`.

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
| `POST /api/ingest` | `Authorization: Bearer <INGEST_TOKEN>` when a token is provisioned; open otherwise (dev only, loud warning at startup) |
| `GET /api/flows`, `GET /api/alerts`, `GET /api/alerts/{id}`, `POST /api/alerts/{id}/resolve` | `Authorization: Bearer <token>` |
| `GET /api/ws` | `?token=<token>` query param (browsers can't set headers on upgrade) |
| `/`, `/login`, `/alerts`, assets | none — the dashboard shell is public; it redirects to login without a token |

Anything else under `/api/*` returns a JSON 404 (never the SPA shell).

## Configuration

| Var | Effect |
|---|---|
| `JWT_SECRET` | HS256 signing key. **Required** — the API refuses to start without it (fail closed). Set a random value (`openssl rand -hex 32`); local runs just export any value. |
| `ADMIN_EMAIL` + `ADMIN_PASSWORD` | Bootstrap admin: hashed (argon2) and upserted at every startup. If either is unset, nothing is seeded and login fails closed (401 for everyone). |
| `INGEST_TOKEN` + `INGEST_TOKENS` | Accepted agent credentials (single + comma-separated list). When any is set, `/api/ingest` requires one as `Bearer`; when unset, ingest stays open with a loud warning. Agents send `--api-token` / `MIST_API_TOKEN` (the operator injects it from the monitor's `apiTokenSecretName`). Rotate by appending the new token, rolling agents, removing the old. Provision high-entropy values anywhere shared. |
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
any environment where the pod network isn't trusted.
