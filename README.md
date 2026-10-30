> Built for the Meta Global Hackathon — https://dev.meta.ai/events/global-hackathon

# mist

mist is a Kubernetes operator that captures per-node network traffic with
eBPF, scores it for anomalies, and surfaces flows and alerts on a dashboard
and as Kubernetes custom resources. All Rust: Aya eBPF sensors, a Tokio +
Axum API with a built-in analyzer, a kube-rs operator, and a Leptos
dashboard.

```
[node] TC ingress/egress eBPF progs (aya)
  → per-CPU flow-count maps ──poll──▶ mist-agent (DaemonSet, per node)
  → pod-IP enrichment via k8s API ──POST /api/ingest──▶ mist-api (Axum)
  → analyzer module scores vs baselines ──▶ Postgres + WebSocket broadcast
  → mist-dashboard (Leptos CSR/WASM) + AnomalyAlert CRs (via operator)
```

## Components

| Component | Crate | Role |
|---|---|---|
| `mist-ebpf` | `crates/mist-ebpf` | Aya TC classifiers (`mist_ingress`/`mist_egress`); per-CPU flow counters, metadata only |
| `mist-agent` | `crates/mist-agent` | Privileged DaemonSet; attaches TC progs, drains maps, enriches pod identity, POSTs batches |
| `mist-api` | `crates/mist-api` | Flow ingest, analyzer (EWMA/spike/scan/beacon), REST + WebSocket, Postgres or in-memory store |
| `mist-operator` | `crates/mist-operator` | Reconciles `TrafficMonitor` → agent DaemonSet; mirrors alerts as `AnomalyAlert` CRs |
| `mist-dashboard` | `crates/mist-dashboard` | Leptos CSR app: login, flows, alerts views; served by mist-api from `dist/` |
| shared types | `crates/mist-types`, `crates/mist-flow` | `FlowRecord`/`Alert` JSON shapes, eBPF wire layout |

See [docs/architecture.md](docs/architecture.md) for the full data-flow,
TC/drain design, panic-freedom rule, and CRD reference.

## Prerequisites

- Rust stable (workspace `rust-version = "1.98"`); **nightly** + `rust-src`
  + `bpf-linker` for the eBPF crate; Linux for anything sensor-related.
- `kind` (or Docker/Colima) + `kubectl` for the local cluster.
- `helm` for the chart path; `trunk` + `wasm32-unknown-unknown` for the
  dashboard bundle.

## Quickstart (kind)

```sh
# 1. Cluster.
kind create cluster --name mist

# 2. Build images + load them (manifests reference :dev, never pulled).
(cd crates/mist-ebpf && cargo +nightly build -Z build-std=core --release)
cp crates/mist-ebpf/target/bpfel-unknown-none/release/mist-ebpf mist-ebpf.o
(cd crates/mist-dashboard && trunk build --release)
docker build -t mist-api:dev -f docker/api.Dockerfile .
docker build -t mist-operator:dev -f docker/operator.Dockerfile .
docker build -t mist-agent:dev -f docker/agent.Dockerfile --build-arg EBPF_OBJECT=mist-ebpf.o .
kind load docker-image mist-api:dev mist-operator:dev mist-agent:dev --name mist

# 3. Manifests (order matters).
kubectl apply -f deploy/agent-rbac.yaml -f deploy/operator-rbac.yaml
kubectl apply -f deploy/crds/
kubectl apply -f deploy/postgres.yaml
kubectl apply -f deploy/api-deployment.yaml -f deploy/operator-deployment.yaml
kubectl apply -f deploy/samples/

# 4. Wait for the control plane; the operator renders the agent DaemonSet.
kubectl -n mist rollout status deployment/mist-operator --timeout=180s
kubectl -n mist rollout status deployment/mist-api --timeout=180s
kubectl -n mist get daemonset mist-agent

# 5. Provision auth (API pod blocks until this exists) + API/dashboard.
kubectl -n mist create secret generic mist-api-auth \
  --from-literal=jwt-secret="$(openssl rand -hex 32)" \
  --from-literal=admin-email=admin@example.com \
  --from-literal=admin-password='s3cret-for-kind' \
  --from-literal=ingest-token='kind-ingest-token'
kubectl -n mist rollout status deployment/mist-api --timeout=180s
kubectl -n mist port-forward svc/mist-api 3000:3000 &
curl localhost:3000/healthz   # -> ok
# Dashboard: open http://localhost:3000/login with the admin above.
```

Or install via Helm (self-contained, no external chart deps):

```sh
helm install mist helm/mist --namespace mist --create-namespace  # namespace value must match
kubectl apply -f deploy/samples/                                    # default TrafficMonitor
```

Full script with curl checks: [docs/demo.md](docs/demo.md).
Install reference (kubectl order, port-forwards, Helm alternative):
[deploy/README.md](deploy/README.md).

## Login / auth

Email + password login. `POST /api/auth/login` issues an HS256 JWT
(24h); send it as `Authorization: Bearer` on REST and as `?token=` on
`/api/ws`. Bootstrap the first user with `ADMIN_EMAIL`/`ADMIN_PASSWORD`
(the API hashes and upserts it at startup); without them login fails
closed. Agents authenticate `POST /api/ingest` with the provisioned
`INGEST_TOKEN` (`Bearer`); unprovisioned ingest stays open (dev only).
All four come from the `mist-api-auth` Secret in-cluster. Details:
[docs/auth.md](docs/auth.md).

## Repo layout

```
crates/            Rust workspace (agent, api, operator, ebpf, dashboard, types, flow)
deploy/            plain manifests: RBAC, CRDs, Deployments, Postgres, samples
helm/mist/         self-contained chart (no external deps; CRDs under crds/)
docker/            multi-stage Dockerfiles (agent, api, operator) + .dockerignore
docs/              architecture, development, auth, demo
.github/workflows/ ci (test/clippy/ebpf/trunk/helm) + e2e-kind + release (GHCR on tags)
```

## Config reference

Verified against the code — no invented knobs.

**mist-api** (`crates/mist-api/src/main.rs`), all env:

| Var | Default | Effect |
|---|---|---|
| `DATABASE_URL` | unset → in-memory store | Postgres URL; runs embedded migrations, persists flows/alerts |
| `OPERATOR_WEBHOOK_URL` | unset → mirroring disabled | Where scored alerts are POSTed (operator `POST /alerts`) |
| `BIND_ADDR` | `0.0.0.0:3000` | Listen address |
| `RUST_LOG` | `info` | Tracing filter |
| `JWT_SECRET` | **required** — API refuses to start without it | HS256 signing key; set to a random value (`openssl rand -hex 32`) |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | unset → login fails closed (401) | Bootstrap admin, argon2-hashed + upserted at startup |
| `INGEST_TOKEN` / `INGEST_TOKENS` | unset → ingest open + loud warning | Accepted agent credentials (single + comma-separated), required as `Bearer` on `/api/ingest` when any is set |
| `TLS_CERT` / `TLS_KEY` | unset → plain HTTP | PEM certificate + key paths; both set serves HTTPS, exactly one set is a startup error |
| `SERVE_DIR` | `crates/mist-dashboard/dist` | Dashboard bundle dir; missing `index.html` → API-only mode |

Detector tuning is compiled defaults, not env
(`DetectorConfig::default`): internal CIDRs `10/8, 172.16/12, 192.168/16,
127/8`; spike ≥5x EWMA and ≥1MB; scan ≥20 ports in 60s; beacon ≥10 samples,
CV ≤0.15, mean gap ≥5s.

**mist-agent** (`crates/mist-agent/src/main.rs`), all CLI flags + env:

| Flag / env | Default | Effect |
|---|---|---|
| `--iface` (repeatable) | auto-detect up, non-`lo` | Interfaces to attach TC progs to |
| `--object` | `mist-ebpf.o` | Path to the compiled eBPF object (`/etc/mist/mist-ebpf.o` in-cluster) |
| `--api-url` | `http://localhost:3000` | Batches POST to `{api-url}/api/ingest` |
| `--api-token` / `MIST_API_TOKEN` | empty → no header | Bearer token for `/api/ingest` (operator injects from Secret) |
| `--interval-secs` | `5` | Drain interval |
| `NODE_NAME` | `/etc/hostname` → `unknown` | Node label on emitted flows |
| `RUST_LOG` | `info` | Tracing filter |

**mist-operator** (`crates/mist-operator/src/main.rs`): `--webhook-addr`
(default `0.0.0.0:8081`), `--namespace` / `OPERATOR_NAMESPACE` (default
`mist`), `--print-crds` (regenerate CRDs). `TrafficMonitor` spec fields:
`watchedNamespaces`, `sampleIntervalSecs` (5), `agentImage`
(`mist-agent:dev`), `nodeSelector`, `apiUrl`, `objectPath`
(`/etc/mist/mist-ebpf.o`), `apiTokenSecretName` (optional Secret for the
agent ingest token).

API routes (`crates/mist-api/src/main.rs` `router`): `GET /healthz`,
`GET /metrics` (public Prometheus scrape), `POST /api/auth/login`,
`GET /api/flows`, `GET /api/alerts`, `GET /api/alerts/{id}`,
`POST /api/alerts/{id}/resolve`, `POST /api/ingest`, `GET /api/ws`.
Unknown `/api/*` paths return a JSON 404 (never the dashboard shell).
Operator webhook: `POST /alerts`.

## Testing

```sh
export RUSTUP_HOME=$PWD/.rustup-home CARGO_HOME=$PWD/.cargo-home PATH=$PWD/.cargo-home/bin:$PATH
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
(cd crates/mist-ebpf && cargo +nightly build -Z build-std=core)
```

## Production gaps / roadmap (honest)

- **Ingest uses one shared token** (`INGEST_TOKEN`; open when
  unprovisioned): keep the API cluster-local unless it is set, and prefer
  per-node credentials or mTLS before treating agents as untrusted. Login
  has no rate limiting yet — keep a rate-limiting ingress in front of any
  internet-facing deployment.
- **Images default to `:dev`** in `deploy/` and chart defaults (build +
  `kind load` locally); tagging `v*` pushes `:tag` + `:latest` to GHCR
  via the release workflow for real clusters.
- **Postgres is single-replica**: a 10Gi PVC in `deploy/` (opt-in via
  `postgres.persistence` in the chart); use a managed DB or add backups
  for anything that matters.
- **Single replica** API/operator by design (live events fan out over an
  in-memory broadcast, so a second API replica would split the WS
  stream — shared pub/sub first); no resource autoscaling. TLS is
  opt-in (`TLS_CERT`/`TLS_KEY`) or terminates at your ingress.
- **Dashboard is CSR-only**: login/flows/alerts views ship and passed a
  scripted in-browser proof (login → live flows → alerts → logout), but
  there is no SSR and no pagination; the proof script isn't committed.
- **eBPF sensor is Linux-only** and needs BTF ≥5.15 + `clsact`;
  load-tested to 229 Gb/s / 16k-flow bursts in kind (see
  `docs/architecture.md`), but the 16k map has no headroom past that —
  size up before dense clusters.

## License

Dual-licensed under [MIT](LICENSE-MIT) and [Apache 2.0](LICENSE-APACHE).
