# mist-agent: privileged per-node eBPF sensor (Linux/amd64 or arm64 only).
# The agent binary is Linux-only; the eBPF object CANNOT be built in this
# Dockerfile. Build it separately with the pinned nightly toolchain plus
# bpf-linker, then make it available at build time next to this Dockerfile:
#
#   cd crates/mist-ebpf && cargo +nightly build -Z build-std=core --release
#   cp target/bpfel-unknown-none/release/mist-ebpf.o <context>/mist-ebpf.o
#   docker build -f docker/agent.Dockerfile --build-arg EBPF_OBJECT=mist-ebpf.o .
#
# (No daemon is available in this environment, so these Dockerfiles are
# validated by review only — they have not been built.)

ARG RUST_VERSION=1.85

FROM rust:${RUST_VERSION}-bookworm AS builder
WORKDIR /src
# Workspace members needed by mist-agent: the binary plus its local libs.
COPY Cargo.toml Cargo.lock ./
COPY crates/mist-agent ./crates/mist-agent
COPY crates/mist-types ./crates/mist-types
COPY crates/mist-flow ./crates/mist-flow
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p mist-agent && \
    cp target/release/mist-agent /usr/local/bin/mist-agent

FROM debian:bookworm-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates iproute2 && \
    rm -rf /var/lib/apt/lists/*
# eBPF object injected at image build time (see header comment).
ARG EBPF_OBJECT=mist-ebpf.o
COPY ${EBPF_OBJECT} /etc/mist/mist-ebpf.o
COPY --from=builder /usr/local/bin/mist-agent /usr/local/bin/mist-agent
# Must match the operator-rendered DaemonSet default
# (crates/mist-operator/testdata/agent-daemonset.yaml).
ENTRYPOINT ["/usr/local/bin/mist-agent", "--object=/etc/mist/mist-ebpf.o"]
