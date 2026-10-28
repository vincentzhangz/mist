# mist-api: Axum flow/alert API + analyzer (stateless; needs Postgres).
# Validated by review only — no container daemon is available in this
# environment, so this Dockerfile has not been built.

ARG RUST_VERSION=1.85

FROM rust:${RUST_VERSION}-bookworm AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates/mist-api ./crates/mist-api
COPY crates/mist-types ./crates/mist-types
COPY crates/mist-flow ./crates/mist-flow
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p mist-api && \
    cp target/release/mist-api /usr/local/bin/mist-api

FROM debian:bookworm-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/bin/mist-api /usr/local/bin/mist-api
# Must match BIND_ADDR / containerPort in deploy/api-deployment.yaml.
EXPOSE 3000
ENV BIND_ADDR=0.0.0.0:3000
ENTRYPOINT ["/usr/local/bin/mist-api"]
