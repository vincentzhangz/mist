# Browser + API proofs (kind)

Scripted end-to-end proofs that run against a live kind cluster. Both
scripts spawn their own `kubectl port-forward`, so the only prerequisites
are a cluster installed per [docs/demo.md](../../docs/demo.md) (through
the auth Secret step) and node:

```sh
cd e2e/browser
npm install
npx playwright install webkit   # one-time browser download
npm run auth    # REST auth: 401/202 ingest, login, JWT flows, agent traffic
npm run ui      # WebKit click-through: login -> flows -> alerts -> logout
```

Each check prints `PASS`/`FAIL`; exit code is nonzero on any failure.

## Configuration

| Env | Default | Meaning |
|---|---|---|
| `MIST_NAMESPACE` | `mist` | Cluster namespace |
| `MIST_PORT` | `3100` (ui) / `3103` (auth) | Local port-forward port |
| `MIST_EMAIL` | `admin@example.com` | Seeded admin (demo Secret) |
| `MIST_PASSWORD` | `s3cret-for-kind` | Seeded admin password |
| `MIST_INGEST_TOKEN` | `kind-ingest-token` | Provisioned ingest token |

WebKit is used instead of Chromium because headless Chromium's compositor
crashes in minimal CI containers; the app itself is engine-agnostic.
