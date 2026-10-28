# Contributing to mist

Thanks for picking this up. The bar is small and explicit:

1. `cargo test --workspace` must pass. Run it with the hermetic env so you
   don't clash with other checkouts:
   `export RUSTUP_HOME=$PWD/.rustup-home CARGO_HOME=$PWD/.cargo-home PATH=$PWD/.cargo-home/bin:$PATH`
2. `cargo clippy --workspace --all-targets` must be pedantic-clean
   (`cargo clippy --workspace --all-targets -- -D warnings`).
3. eBPF changes must additionally build for the BPF target and keep the
   panic-freedom rule (`crates/mist-ebpf/Cargo.toml` documents it):
   no panicking paths in `mist-ebpf`; intentional wrapping uses explicit
   `wrapping_*` calls.
4. Operator changes that touch the CRDs must regenerate
   `deploy/crds/` (`cargo run -p mist-operator -- --print-crds`) and update
   the Helm copies under `helm/mist/crds/` to match.

Keep patches narrow, match the surrounding code style (workspace lints
already enforce `unsafe_code = "warn"` plus Clippy `all` + `pedantic`),
and update `docs/` when you change behavior a user can observe.
