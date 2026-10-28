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

Tokens are HS256, `sub` = email, 24h expiry.

## Which routes need the token

| Endpoint | Auth |
|---|---|
| `GET /healthz` | none |
| `POST /api/auth/login` | none |
| `POST /api/ingest` | none — public by design for now (see below) |
| `GET /api/flows`, `GET /api/alerts`, `GET /api/alerts/{id}`, `POST /api/alerts/{id}/resolve` | `Authorization: Bearer <token>` |
| `GET /api/ws` | `?token=<token>` query param (browsers can't set headers on upgrade) |
| `/`, `/login`, `/flows`, `/alerts`, assets | none — the dashboard shell is public; it redirects to login without a token |

Anything else under `/api/*` returns a JSON 404 (never the SPA shell).

## Configuration

| Var | Effect |
|---|---|
| `JWT_SECRET` | HS256 signing key. Unset/empty falls back to an insecure dev default (`dev-secret-change-me`) with a loud startup warning — set a random value anywhere shared. |
| `ADMIN_EMAIL` + `ADMIN_PASSWORD` | Bootstrap admin: hashed (argon2) and upserted at every startup. If either is unset, nothing is seeded and login fails closed (401 for everyone). |
| `DATABASE_URL` | With Postgres the users table persists (migration `002_auth.sql`); without it the in-memory store still accepts the seeded admin, but users vanish on restart. |

## Consequences

- Keep `mist-api` cluster-local until agent auth exists: anyone who can
  reach it can inject fake flow batches via public `/api/ingest`.
- The operator webhook (`POST /alerts` on `:8081`) is unauthenticated by
  design and must stay cluster-internal (no external Service/ingress in
  `deploy/` or the chart).
- The `mist-dev-password` Postgres credential in `deploy/postgres.yaml`
  (and the chart default) is dev-only; override it anywhere shared.

## Roadmap (not implemented)

Agent ingest still needs a provisioned credential (per-node token or
mTLS) — that is the remaining TODO before the API can face anything
less trusted than the cluster network.
