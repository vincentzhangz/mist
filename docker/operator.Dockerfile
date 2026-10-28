# mist-operator: kube-rs controller + alert webhook.
# Validated by review only — no container daemon is available in this
# environment, so this Dockerfile has not been built.

ARG RUST_VERSION=1.85

FROM rust:${RUST_VERSION}-bookworm AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates/mist-operator ./crates/mist-operator
COPY crates/mist-types ./crates/mist-types
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p mist-operator && \
    cp target/release/mist-operator /usr/local/bin/mist-operator

FROM debian:bookworm-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/bin/mist-operator /usr/local/bin/mist-operator
# Must match --webhook-addr / containerPort in deploy/operator-deployment.yaml.
EXPOSE 8081
ENTRYPOINT ["/usr/local/bin/mist-operator"]
