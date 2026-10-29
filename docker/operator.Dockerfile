# mist-operator: kube-rs controller + alert webhook.
# Validated by review only — no container daemon is available in this
# environment, so this Dockerfile has not been built.

ARG RUST_VERSION=1.99

FROM rust:${RUST_VERSION}-bookworm AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
# The whole crates/ tree: cargo fails when workspace members listed in the
# root Cargo.toml are absent, even for `cargo build -p mist-operator`.
COPY crates/ ./crates/
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p mist-operator && \
    cp target/release/mist-operator /usr/local/bin/mist-operator

FROM debian:bookworm-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin mist && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/bin/mist-operator /usr/local/bin/mist-operator
# Non-root user to satisfy the runAsNonRoot pod securityContext.
USER 10001:10001
# Must match --webhook-addr / containerPort in deploy/operator-deployment.yaml.
EXPOSE 8081
ENTRYPOINT ["/usr/local/bin/mist-operator"]
