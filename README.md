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

- Rust stable (workspace `rust-version = "1.85"`); **nightly** + `rust-src`
  + `bpf-linker` for the eBPF crate; Linux for anything sensor-related.
- `kind` (or Docker/Colima) + `kubectl` for the local cluster.
- `helm` for the chart path; `trunk` + `wasm32-unknown-unknown` for the
  dashboard bundle.

## Quickstart (kind)

```sh
# 1. Cluster + manifests (order matters).
kind create cluster --name mist
kubectl apply -f deploy/agent-rbac.yaml -f deploy/operator-rbac.yaml
kubectl apply -f deploy/crds/
kubectl apply -f deploy/postgres.yaml
kubectl apply -f deploy/api-deployment.yaml -f deploy/operator-deployment.yaml
kubectl apply -f deploy/samples/

# 2. Wait for the control plane; the operator renders the agent DaemonSet.
kubectl -n mist rollout status deployment/mist-operator --timeout=180s
kubectl -n mist rollout status deployment/mist-api --timeout=180s
kubectl -n mist get daemonset mist-agent

# 3. API + dashboard.
kubectl -n mist port-forward svc/mist-api 3000:3000 &
curl localhost:3000/healthz   # -> ok
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
closed. `POST /api/ingest` stays public until agent credentials are
designed — keep the API cluster-local. Details: [docs/auth.md](docs/auth.md).

## Repo layout

```
crates/            Rust workspace (agent, api, operator, ebpf, dashboard, types, flow)
deploy/            plain manifests: RBAC, CRDs, Deployments, Postgres, samples
helm/mist/         self-contained chart (no external deps; CRDs under crds/)
docker/            multi-stage Dockerfiles (agent, api, operator) + .dockerignore
docs/              architecture, development, auth, demo
.github/workflows/ ci (test/clippy/ebpf/trunk/helm) + experimental e2e-kind
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
| `JWT_SECRET` | unset → insecure dev default + loud warning | HS256 signing key; MUST be set to a random value anywhere shared |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | unset → login fails closed (401) | Bootstrap admin, argon2-hashed + upserted at startup |
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
| `--interval-secs` | `5` | Drain interval |
| `NODE_NAME` | `/etc/hostname` → `unknown` | Node label on emitted flows |
| `RUST_LOG` | `info` | Tracing filter |

**mist-operator** (`crates/mist-operator/src/main.rs`): `--webhook-addr`
(default `0.0.0.0:8081`), `--namespace` / `OPERATOR_NAMESPACE` (default
`mist`), `--print-crds` (regenerate CRDs). `TrafficMonitor` spec fields:
`watchedNamespaces`, `sampleIntervalSecs` (5), `agentImage`
(`mist-agent:dev`), `nodeSelector`, `apiUrl`, `objectPath`
(`/etc/mist/mist-ebpf.o`).

API routes (`crates/mist-api/src/main.rs` `router`): `GET /healthz`,
`POST /api/auth/login`, `GET /api/flows`, `GET /api/alerts`,
`GET /api/alerts/{id}`, `POST /api/alerts/{id}/resolve`,
`POST /api/ingest`, `GET /api/ws`. Unknown `/api/*` paths return a
JSON 404 (never the dashboard shell). Operator webhook: `POST /alerts`.

## Testing

```sh
export RUSTUP_HOME=$PWD/.rustup-home CARGO_HOME=$PWD/.cargo-home PATH=$PWD/.cargo-home/bin:$PATH
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
(cd crates/mist-ebpf && cargo +nightly build -Z build-std=core)
```

## Production gaps / roadmap (honest)

- **Ingest is still public**: `/api/ingest` takes no credential yet
  (agent auth is TODO); keep the API cluster-local.
- **Images are `:dev` placeholders** in `deploy/` and chart defaults;
  nothing here has been pushed to a registry, and the Dockerfiles have
  only been reviewed, never built (no daemon in this environment).
- **Postgres is dev-grade**: `emptyDir` in `deploy/` (chart default too);
  enable `postgres.persistence` or use a managed DB.
- **Single replica** API/operator; no TLS, no resource autoscaling, no
  metrics endpoint; eBPF map sizing under load untested.
- **Dashboard is CSR-only**: login/flows/alerts views ship, but there is
  no SSR, no pagination, and no in-browser click-through test yet.
- **eBPF sensor is Linux-only** and needs BTF ≥5.15 + `clsact`; the kind
  e2e stays experimental until images are published.

## License

Dual-licensed under [MIT](LICENSE-MIT) and [Apache 2.0](LICENSE-APACHE).
