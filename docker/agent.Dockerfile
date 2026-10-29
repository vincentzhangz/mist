# mist-agent: privileged per-node eBPF sensor (Linux/amd64 or arm64 only).
# The agent binary is Linux-only; the eBPF object CANNOT be built in this
# Dockerfile. Build it separately with the pinned nightly toolchain plus
# bpf-linker, then make it available at build time next to this Dockerfile:
#
#   cd crates/mist-ebpf && cargo +nightly build -Z build-std=core --release
#   cp target/bpfel-unknown-none/release/mist-ebpf <context>/mist-ebpf.o
#   (the linker emits no .o extension; renamed on copy)
#   docker build -f docker/agent.Dockerfile --build-arg EBPF_OBJECT=mist-ebpf.o .
#
# (No daemon is available in this environment, so these Dockerfiles are
# validated by review only — they have not been built.)

ARG RUST_VERSION=1.85

FROM rust:${RUST_VERSION}-bookworm AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
# The whole crates/ tree: cargo fails when workspace members listed in the
# root Cargo.toml are absent, even for `cargo build -p mist-agent`.
COPY crates/ ./crates/
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
# Bare binary: the operator-rendered DaemonSet supplies its own args, and k8s
# args append to ENTRYPOINT — baking flags here would pass them twice and
# clap would reject the duplicates.
ENTRYPOINT ["/usr/local/bin/mist-agent"]
