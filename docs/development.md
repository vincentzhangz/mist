# Development

## Prerequisites

- Rust stable (workspace pins `rust-version = "1.98"`, edition 2024;
  CI and Dockerfiles pin the exact toolchain `1.99.1`/`1.99`) plus
  a **nightly** toolchain with `rust-src` for `crates/mist-ebpf`, and the
  `bpf-linker` linker (`cargo +nightly install bpf-linker`).
- `trunk` 0.22.1 + `wasm32-unknown-unknown` target for the dashboard
  bundle (`cd crates/mist-dashboard && trunk build --release`).
- Linux for anything eBPF: the sensor cannot build or run on macOS.
  Use a Linux VM (e.g. Lima) or a Linux dev machine.
- `kind` (or Docker/Colima) + `kubectl` for the cluster loop. The local
  context used here is `kind-mist`.

## Hermetic cargo home

Parallel checkouts share nothing when each shell exports:

```sh
export RUSTUP_HOME=$PWD/.rustup-home CARGO_HOME=$PWD/.cargo-home PATH=$PWD/.cargo-home/bin:$PATH
```

Install rustup once per checkout if `cargo` is missing:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
```

## Common tasks

```sh
# Build / test / lint userspace (the merge bar — see CONTRIBUTING.md).
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings

# eBPF crate only (detached workspace; config in crates/mist-ebpf/.cargo/config.toml
# pins target bpfel-unknown-none + linker bpf-linker). Run with cwd INSIDE the crate.
cd crates/mist-ebpf && cargo +nightly build -Z build-std=core

# Print the CRDs after changing crates/mist-operator/src/crd.rs, then split
# into deploy/crds/ and copy to helm/mist/crds/ (keep all three in sync).
cargo run -p mist-operator -- --print-crds > /tmp/crds.yaml

# Run the API locally against port-forwarded Postgres (see deploy/README.md).
kubectl -n mist port-forward svc/mist-postgres 5432:5432 &
DATABASE_URL=postgres://mist:mist-dev-password@localhost:5432/mist \
  OPERATOR_WEBHOOK_URL=http://localhost:8081/alerts \
  ADMIN_EMAIL=admin@example.com ADMIN_PASSWORD=dev-only \
  JWT_SECRET=dev-only \
  BIND_ADDR=127.0.0.1:3000 \
  cargo run -p mist-api
# JWT_SECRET is required (any value for local dev); unset INGEST_TOKEN
# leaves /api/ingest open.
# The API serves the dashboard from crates/mist-dashboard/dist when the
# trunk bundle exists there (API-only mode otherwise); open
# http://127.0.0.1:3000/login with the admin above.
```

## Linux VM notes

- The agent is Linux-only at runtime: on other OSes it exits with
  `mist-agent requires Linux (eBPF); refusing to run on this platform`.
  Its pure helpers (`convert::` in `crates/mist-agent/src/main.rs`) are
  unit-tested on any host.
- The VM kernel needs BTF enabled and ≥5.15 for CO-RE; TC `clsact` qdisc
  support is required on the attach interfaces. kind's default node image
  qualifies — if `tc qdisc add clsact` fails there, the sensor design must
  change before anything downstream.
- While the sensor is unavailable, API/dashboard work is unblocked: POST
  synthetic `FlowBatch` JSON to `/api/ingest` and drive the analyzer,
  REST, and WebSocket paths without a cluster.
