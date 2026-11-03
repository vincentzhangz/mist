//! mist-agent: per-node eBPF traffic sensor.
//!
//! Loads the compiled `mist-ebpf` object, attaches its TC ingress/egress
//! classifiers to network interfaces, drains per-flow counters, attributes
//! endpoints to pods via the Kubernetes API, and ships batches to mist-api.
//! Linux-only at runtime; other platforms get a stub that fails with a clear
//! message so the workspace still checks everywhere.

use clap::Parser;
use tracing_subscriber::EnvFilter;

#[cfg_attr(
    all(not(test), not(target_os = "linux")),
    allow(
        dead_code,
        reason = "only the Linux loader calls these; tests cover them elsewhere"
    )
)]
mod convert;
#[cfg(target_os = "linux")]
mod linux;
mod tls;

#[derive(Debug, Parser)]
#[command(name = "mist-agent", about = "mist per-node eBPF traffic agent")]
pub(crate) struct Args {
    /// Network interface to attach to. Repeatable; empty means auto-detect
    /// all up, non-loopback interfaces.
    #[arg(long)]
    iface: Vec<String>,
    /// Path to the compiled eBPF object file.
    #[arg(long, default_value = "mist-ebpf.o")]
    object: std::path::PathBuf,
    /// Base URL of the mist-api server.
    #[arg(long, default_value = "http://localhost:3000")]
    api_url: String,
    /// Bearer token for `POST /api/ingest`. Also read from `MIST_API_TOKEN`
    /// (the operator injects it from a Secret when the monitor names one);
    /// empty sends no header, for APIs without `INGEST_TOKEN` provisioned.
    #[arg(long, env = "MIST_API_TOKEN", default_value = "")]
    api_token: String,
    /// Drain interval in seconds.
    #[arg(long, default_value_t = 5)]
    interval_secs: u64,
    /// PEM CA bundle the API server's certificate must chain to. Also read
    /// from `MIST_TLS_CA_CERT`. Unset means system roots (fine for public
    /// PKI; self-signed API certs need this).
    #[arg(long, env = "MIST_TLS_CA_CERT")]
    tls_ca_cert: Option<std::path::PathBuf>,
    /// PEM client certificate for mTLS ingest. Also read from
    /// `MIST_TLS_CERT`. Requires `--tls-key` (and the API's `CLIENT_CA_CERT`
    /// to chain it to).
    #[arg(long, env = "MIST_TLS_CERT")]
    tls_cert: Option<std::path::PathBuf>,
    /// PEM client private key for mTLS ingest. Also read from `MIST_TLS_KEY`.
    #[arg(long, env = "MIST_TLS_KEY")]
    tls_key: Option<std::path::PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // rustls auto-detect panics when both ring and aws-lc-rs are enabled (our
    // tree has both via kube/reqwest/sqlx); pin an explicit process default.
    let _ = rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    let args = Args::parse();
    #[cfg(target_os = "linux")]
    return run(args).await;
    #[cfg(not(target_os = "linux"))]
    return run(args);
}

#[cfg(target_os = "linux")]
async fn run(args: Args) -> anyhow::Result<()> {
    linux::run(&args).await
}

#[cfg(not(target_os = "linux"))]
fn run(_args: Args) -> anyhow::Result<()> {
    anyhow::bail!("mist-agent requires Linux (eBPF); refusing to run on this platform")
}
