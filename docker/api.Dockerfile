# mist-api: Axum flow/alert API + analyzer (stateless; needs Postgres).
# Serves the trunk-built dashboard SPA from /srv/dashboard; build the bundle
# first (`trunk build --release` in crates/mist-dashboard) — the COPY below
# fails on a fresh checkout without it.

ARG RUST_VERSION=1.99

FROM rust:${RUST_VERSION}-bookworm AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
# The whole crates/ tree: cargo fails when workspace members listed in the
# root Cargo.toml are absent, even for `cargo build -p mist-api`.
COPY crates/ ./crates/
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p mist-api && \
    cp target/release/mist-api /usr/local/bin/mist-api

FROM debian:bookworm-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin mist && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/bin/mist-api /usr/local/bin/mist-api
# Dashboard SPA bundle baked in; the API serves SERVE_DIR at / with
# index.html fallback (API-only mode when the dir is absent).
COPY crates/mist-dashboard/dist/ /srv/dashboard/
ENV SERVE_DIR=/srv/dashboard
# Non-root user to satisfy the runAsNonRoot pod securityContext.
USER 10001:10001
# Must match BIND_ADDR / containerPort in deploy/api-deployment.yaml.
EXPOSE 3000
ENV BIND_ADDR=0.0.0.0:3000
ENTRYPOINT ["/usr/local/bin/mist-api"]
