# Security policy

mist is pre-production demo software (see the production-gaps section in
the [README](README.md)). Treat it accordingly: do not expose the API,
the operator webhook, or Postgres to untrusted networks.

## Scope

In scope: the Rust services (`mist-agent`, `mist-api`, `mist-operator`,
`mist-ebpf`), the Helm chart, manifests, and container builds in this repo.

## Reporting

Do not open a public issue for a suspected vulnerability. Email the
maintainer privately (see the commit history for a contact address),
describe the affected component and how to reproduce, and allow time to
fix before disclosing.

## Known posture (not vulnerabilities, but be aware)

- The API currently has **no authentication**: every endpoint, including
  `POST /api/ingest`, is unauthenticated by design for now
  (see [docs/auth.md](docs/auth.md)).
- `deploy/postgres.yaml` ships a dev-only password (`mist-dev-password`).
  Override it for any shared environment.
