//! mist-agent: per-node eBPF traffic sensor.
//!
//! Loads the compiled `mist-ebpf` object, attaches its TC ingress/egress
//! classifiers to network interfaces, drains per-flow counters, attributes
//! endpoints to pods via the Kubernetes API, and ships batches to mist-api.
//! Linux-only at runtime; other platforms get a stub that fails with a clear
//! message so the workspace still checks everywhere.

use clap::Parser;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "mist-agent", about = "mist per-node eBPF traffic agent")]
struct Args {
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
    /// Drain interval in seconds.
    #[arg(long, default_value_t = 5)]
    interval_secs: u64,
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

/// Pure conversion helpers shared by all platforms (and unit-tested on host).
#[cfg_attr(
    all(not(test), not(target_os = "linux")),
    allow(
        dead_code,
        reason = "only the Linux loader calls these; tests cover them elsewhere"
    )
)]
mod convert {
    use std::{
        collections::HashMap,
        net::{IpAddr, Ipv4Addr},
    };

    use mist_flow::{FlowKeyWire, FlowStatsWire};
    use mist_types::{FlowKey, FlowRecord, PodRef, TrafficDirection};

    /// Per-flow counters aggregated across CPUs.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct AggStats {
        pub packets: u64,
        pub bytes: u64,
        pub start_ns: u64,
        pub last_ns: u64,
        pub tcp_flags: u8,
    }

    /// Sum per-CPU counters. Returns `None` when there are no values.
    #[must_use]
    pub fn aggregate(values: &[FlowStatsWire]) -> Option<AggStats> {
        let mut agg = AggStats {
            packets: 0,
            bytes: 0,
            start_ns: u64::MAX,
            last_ns: 0,
            tcp_flags: 0,
        };
        let mut any = false;
        for value in values {
            any = true;
            agg.packets = agg.packets.saturating_add(value.packets);
            agg.bytes = agg.bytes.saturating_add(value.bytes);
            agg.start_ns = agg.start_ns.min(value.start_ns);
            agg.last_ns = agg.last_ns.max(value.last_ns);
            agg.tcp_flags |= value.tcp_flags;
        }
        any.then_some(agg)
    }

    /// Convert one drained flow to an API record. Boot-nanosecond timestamps
    /// map onto unix millis via the boot-time anchor; unknown direction
    /// encodings fall back to ingress.
    pub fn wire_to_record(
        key: &FlowKeyWire,
        agg: &AggStats,
        node: &str,
        boot_unix_ms: u64,
        pods: &HashMap<IpAddr, PodRef>,
    ) -> FlowRecord {
        // Wire fields hold `from_be_bytes` numerics, which `Ipv4Addr::from`
        // interprets identically; no byte swap is needed.
        let src_ip = IpAddr::V4(Ipv4Addr::from(key.src_ip));
        let dst_ip = IpAddr::V4(Ipv4Addr::from(key.dst_ip));
        let to_ms = |ns: u64| boot_unix_ms.saturating_add(ns / 1_000_000);
        FlowRecord {
            key: FlowKey {
                src_ip,
                src_port: key.src_port,
                dst_ip,
                dst_port: key.dst_port,
                protocol: key.protocol,
            },
            direction: match key.direction {
                1 => TrafficDirection::Egress,
                _ => TrafficDirection::Ingress,
            },
            bytes: agg.bytes,
            packets: agg.packets,
            start_unix_ms: to_ms(agg.start_ns),
            last_seen_unix_ms: to_ms(agg.last_ns),
            node: node.to_owned(),
            src_pod: pods.get(&src_ip).cloned(),
            dst_pod: pods.get(&dst_ip).cloned(),
        }
    }

    /// Parse the first field of `/proc/uptime` (seconds since boot) into
    /// whole milliseconds, without floating point.
    #[must_use]
    pub fn parse_uptime_ms(text: &str) -> Option<u64> {
        let field = text.split_ascii_whitespace().next()?;
        let (secs_str, frac_str) = match field.split_once('.') {
            Some((secs, frac)) => (secs, frac),
            None => (field, ""),
        };
        let secs_ms = secs_str.parse::<u64>().ok()?.checked_mul(1_000)?;
        // Normalize the fraction to exactly 3 digits (millis).
        let mut frac_buf = [b'0'; 3];
        let frac_bytes = frac_str.as_bytes();
        let digits = frac_bytes.len().min(3);
        frac_buf[..digits].copy_from_slice(&frac_bytes[..digits]);
        let frac_ms = std::str::from_utf8(&frac_buf).ok()?.parse::<u64>().ok()?;
        secs_ms.checked_add(frac_ms)
    }

    /// Unix millis at boot, from uptime millis and current unix millis.
    #[must_use]
    pub const fn boot_unix_ms(uptime_ms: u64, now_unix_ms: u64) -> u64 {
        now_unix_ms.saturating_sub(uptime_ms)
    }

    /// Select interfaces to attach to: skip loopback and interfaces that are
    /// down. Input is `(name, operstate)` pairs.
    #[must_use]
    pub fn select_interfaces(entries: &[(String, String)]) -> Vec<String> {
        entries
            .iter()
            .filter(|(name, state)| {
                name != "lo"
                    && !matches!(
                        state.as_str(),
                        "down" | "lowerlayerdown" | "dormant" | "testing"
                    )
            })
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// Node name from the downward API, falling back to the hostname.
    #[must_use]
    pub fn node_name() -> String {
        std::env::var("NODE_NAME")
            .ok()
            .filter(|name| !name.is_empty())
            .or_else(|| {
                std::fs::read_to_string("/etc/hostname")
                    .ok()
                    .map(|hostname| hostname.trim().to_owned())
                    .filter(|hostname| !hostname.is_empty())
            })
            .unwrap_or_else(|| "unknown".to_owned())
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        borrow::{Borrow, BorrowMut},
        collections::HashMap,
        ffi::CString,
        net::IpAddr,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    use anyhow::Context as _;
    use aya::{
        Ebpf, EbpfLoader,
        maps::{PerCpuArray, PerCpuHashMap},
        programs::{SchedClassifier, TcAttachType, tc},
    };
    use k8s_openapi::api::core::v1::Pod;
    use kube::{Api, Client, api::ListParams};
    use mist_flow::{FlowKeyWire, FlowStatsWire};
    use mist_types::{FlowBatch, PodRef};

    use super::convert;
    use crate::Args;

    /// Newtypes so the agent crate (which owns them) can implement the foreign
    /// `aya::Pod` trait for the shared wire layout.
    #[repr(transparent)]
    #[derive(Clone, Copy)]
    struct Key(FlowKeyWire);

    #[repr(transparent)]
    #[derive(Clone, Copy)]
    struct Stats(FlowStatsWire);

    // SAFETY: transparent wrappers over `repr(C)` integer-only structs: every
    // bit pattern is a valid value, and both are `Copy`.
    #[allow(
        unsafe_code,
        reason = "aya requires Pod marker impls for map keys/values"
    )]
    unsafe impl aya::Pod for Key {}
    // SAFETY: see above.
    #[allow(
        unsafe_code,
        reason = "aya requires Pod marker impls for map keys/values"
    )]
    unsafe impl aya::Pod for Stats {}

    /// Pod-IP attribution cache. Works without a cluster (empty cache) so the
    /// agent still runs on bare-metal dev machines.
    struct PodCache {
        client: Option<Client>,
        entries: HashMap<IpAddr, PodRef>,
        last_refresh: Option<Instant>,
    }

    impl PodCache {
        async fn new() -> Self {
            match Client::try_default().await {
                Ok(client) => Self {
                    client: Some(client),
                    entries: HashMap::new(),
                    last_refresh: None,
                },
                Err(error) => {
                    tracing::warn!(?error, "no Kubernetes API; pod attribution disabled");
                    Self {
                        client: None,
                        entries: HashMap::new(),
                        last_refresh: None,
                    }
                }
            }
        }

        async fn refresh_if_stale(&mut self) {
            let stale = self
                .last_refresh
                .is_none_or(|at| at.elapsed() > Duration::from_secs(30));
            if !stale {
                return;
            }
            self.last_refresh = Some(Instant::now());
            let Some(client) = &self.client else {
                return;
            };
            let pods: Api<Pod> = Api::all(client.clone());
            match pods.list(&ListParams::default()).await {
                Ok(list) => {
                    let mut entries = HashMap::new();
                    for pod in &list.items {
                        let Some(status) = &pod.status else {
                            continue;
                        };
                        let name = pod.metadata.name.clone().unwrap_or_default();
                        if name.is_empty() {
                            continue;
                        }
                        let namespace = pod.metadata.namespace.clone().unwrap_or_default();
                        let mut ips = Vec::new();
                        ips.extend(status.pod_ip.clone());
                        if let Some(pod_ips) = &status.pod_ips {
                            ips.extend(pod_ips.iter().map(|entry| entry.ip.clone()));
                        }
                        for ip in ips {
                            if let Ok(addr) = ip.parse::<IpAddr>() {
                                entries.insert(
                                    addr,
                                    PodRef {
                                        namespace: namespace.clone(),
                                        name: name.clone(),
                                    },
                                );
                            }
                        }
                    }
                    tracing::debug!(pods = entries.len(), "refreshed pod cache");
                    self.entries = entries;
                }
                Err(error) => tracing::warn!(?error, "pod list failed; keeping cache"),
            }
        }
    }

    pub(super) async fn run(args: &Args) -> anyhow::Result<()> {
        let node = convert::node_name();
        let data = std::fs::read(&args.object)
            .with_context(|| format!("reading eBPF object {}", args.object.display()))?;
        let mut bpf = EbpfLoader::default()
            .load(&data)
            .context("loading eBPF object into kernel")?;

        let ifaces = if args.iface.is_empty() {
            detect_interfaces()
        } else {
            args.iface.clone()
        };
        anyhow::ensure!(!ifaces.is_empty(), "no network interfaces to attach to");
        attach_interfaces(&mut bpf, &ifaces)?;

        // `take_map` moves each map out of `bpf`, so the two handles are owned
        // instead of borrowing `bpf` across each other (two `map_mut` borrows
        // won't compile).
        let mut flows = PerCpuHashMap::<_, Key, Stats>::try_from(
            bpf.take_map("FLOWS").context("finding FLOWS map")?,
        )?;
        let stats_map =
            PerCpuArray::<_, u64>::try_from(bpf.take_map("STATS").context("finding STATS map")?)?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .context("building HTTP client")?;
        let ingest_url = format!("{}/api/ingest", args.api_url.trim_end_matches('/'));

        let mut pods = PodCache::new().await;
        let mut ticker = tokio::time::interval(Duration::from_secs(args.interval_secs));
        loop {
            ticker.tick().await;
            pods.refresh_if_stale().await;
            let batch = drain(&mut flows, &node, &pods.entries)?;
            let updated = read_stat(&stats_map, 0)?;
            let skipped = read_stat(&stats_map, 1)?;
            let map_full = read_stat(&stats_map, 2)?;
            tracing::info!(
                flows = batch.flows.len(),
                updated,
                skipped,
                map_full,
                %node,
                "drained flows"
            );
            if !batch.flows.is_empty()
                && let Err(error) = http.post(&ingest_url).json(&batch).send().await
            {
                tracing::warn!(?error, url = %ingest_url, "ingest shipment failed");
            }
        }
    }

    /// Snapshot all flows then remove each key. A packet counted between our
    /// read and remove is lost (small undercount); in return the map stays
    /// bounded without kernel-side LRU.
    fn drain<T: BorrowMut<aya::maps::MapData>>(
        flows: &mut PerCpuHashMap<T, Key, Stats>,
        node: &str,
        pods: &HashMap<IpAddr, PodRef>,
    ) -> anyhow::Result<FlowBatch> {
        let mut batch = FlowBatch {
            node: node.to_owned(),
            flows: Vec::new(),
        };
        let boot_ms = boot_unix_ms_now();
        let mut drained = Vec::new();
        for entry in flows.iter() {
            let (key, values) = entry?;
            let wire_values: Vec<FlowStatsWire> = values.iter().map(|stats| stats.0).collect();
            if let Some(agg) = convert::aggregate(&wire_values) {
                batch
                    .flows
                    .push(convert::wire_to_record(&key.0, &agg, node, boot_ms, pods));
            }
            drained.push(key);
        }
        for key in &drained {
            if let Err(error) = flows.remove(key) {
                tracing::debug!(?error, "flow remove raced with kernel insert");
            }
        }
        Ok(batch)
    }

    fn read_stat<T: Borrow<aya::maps::MapData>>(
        stats: &PerCpuArray<T, u64>,
        slot: u32,
    ) -> anyhow::Result<u64> {
        let mut total = 0u64;
        for value in stats.get(&slot, 0)?.iter() {
            total = total.saturating_add(*value);
        }
        Ok(total)
    }

    fn boot_unix_ms_now() -> u64 {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
            .unwrap_or(0);
        let uptime_ms = std::fs::read_to_string("/proc/uptime")
            .ok()
            .and_then(|text| convert::parse_uptime_ms(&text))
            .unwrap_or(0);
        convert::boot_unix_ms(uptime_ms, now_ms)
    }

    fn detect_interfaces() -> Vec<String> {
        let mut entries = Vec::new();
        let Ok(read_dir) = std::fs::read_dir("/sys/class/net") else {
            return Vec::new();
        };
        for entry in read_dir.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let state = std::fs::read_to_string(entry.path().join("operstate"))
                .map(|contents| contents.trim().to_owned())
                .unwrap_or_default();
            entries.push((name, state));
        }
        convert::select_interfaces(&entries)
    }

    /// Attach both classifiers to every interface: each program is loaded once
    /// and then attached per interface (re-loading an attached program fails,
    /// and each `program_mut` borrow must end before the next begins).
    fn attach_interfaces(bpf: &mut Ebpf, ifaces: &[String]) -> anyhow::Result<()> {
        let mut names = Vec::with_capacity(ifaces.len());
        for iface in ifaces {
            let iface_c = CString::new(iface.as_str()).context("interface name contains NUL")?;
            if let Err(error) = tc::qdisc_add_clsact(iface_c.as_c_str()) {
                tracing::debug!(?error, iface, "clsact qdisc already present or unsupported");
            }
            names.push(iface_c);
        }
        for (prog_name, attach_type) in [
            ("mist_ingress", TcAttachType::Ingress),
            ("mist_egress", TcAttachType::Egress),
        ] {
            let program: &mut SchedClassifier = bpf
                .program_mut(prog_name)
                .with_context(|| format!("finding program {prog_name}"))?
                .try_into()
                .with_context(|| format!("program {prog_name} is not a TC classifier"))?;
            program
                .load()
                .with_context(|| format!("loading {prog_name}"))?;
            for iface_c in &names {
                program
                    .attach(iface_c.as_c_str(), attach_type)
                    .with_context(|| {
                        format!("attaching {prog_name} to {}", iface_c.to_string_lossy())
                    })?;
            }
            tracing::info!(prog = prog_name, ifaces = ?ifaces, "attached classifier");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use mist_flow::{FlowKeyWire, FlowStatsWire};

    use super::convert::*;

    fn key() -> FlowKeyWire {
        FlowKeyWire {
            src_ip: u32::from_be_bytes([10, 0, 1, 4]),
            dst_ip: u32::from_be_bytes([10, 0, 2, 9]),
            src_port: 51234,
            dst_port: 443,
            protocol: 6,
            direction: 1,
            pad: [0; 2],
        }
    }

    fn stats(packets: u64, bytes: u64, start_ns: u64, last_ns: u64, flags: u8) -> FlowStatsWire {
        FlowStatsWire {
            packets,
            bytes,
            start_ns,
            last_ns,
            tcp_flags: flags,
            pad: [0; 7],
        }
    }

    #[test]
    fn aggregate_sums_and_folds() {
        let agg = aggregate(&[
            stats(10, 1000, 5_000_000_000, 7_000_000_000, 0x02),
            stats(20, 3000, 6_000_000_000, 9_000_000_000, 0x10),
        ])
        .unwrap();
        assert_eq!(agg.packets, 30);
        assert_eq!(agg.bytes, 4000);
        assert_eq!(agg.start_ns, 5_000_000_000);
        assert_eq!(agg.last_ns, 9_000_000_000);
        assert_eq!(agg.tcp_flags, 0x12);
    }

    #[test]
    fn aggregate_empty_is_none() {
        assert!(aggregate(&[]).is_none());
    }

    #[test]
    fn converts_wire_record_with_pod_attribution() {
        let mut pods = std::collections::HashMap::new();
        pods.insert(
            std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 1, 4)),
            mist_types::PodRef {
                namespace: "prod".to_owned(),
                name: "api-0".to_owned(),
            },
        );
        let agg = aggregate(&[stats(3, 300, 1_000_000_000, 2_000_000_000, 0)]).unwrap();
        let record = wire_to_record(&key(), &agg, "node-1", 1_700_000_000_000, &pods);
        assert_eq!(record.key.src_ip.to_string(), "10.0.1.4");
        assert_eq!(record.key.dst_ip.to_string(), "10.0.2.9");
        assert_eq!(record.key.src_port, 51234);
        assert_eq!(record.key.dst_port, 443);
        assert_eq!(record.direction, mist_types::TrafficDirection::Egress);
        assert_eq!(record.packets, 3);
        assert_eq!(record.bytes, 300);
        assert_eq!(record.start_unix_ms, 1_700_000_001_000);
        assert_eq!(record.last_seen_unix_ms, 1_700_000_002_000);
        assert_eq!(record.node, "node-1");
        assert_eq!(record.src_pod.as_ref().unwrap().name, "api-0");
        assert!(record.dst_pod.is_none());
    }

    #[test]
    fn boot_time_math() {
        assert_eq!(parse_uptime_ms("123.45 678.90\n"), Some(123_450));
        assert_eq!(parse_uptime_ms("7 1\n"), Some(7_000));
        assert_eq!(parse_uptime_ms("0.000001 0\n"), Some(0));
        assert_eq!(parse_uptime_ms(""), None);
        assert_eq!(parse_uptime_ms("abc"), None);
        assert_eq!(boot_unix_ms(100_000, 1_000_000), 900_000);
        assert_eq!(boot_unix_ms(2_000_000, 1_000_000), 0); // saturates
    }

    #[test]
    fn selects_sensible_interfaces() {
        let entries = vec![
            ("lo".to_owned(), "up".to_owned()),
            ("eth0".to_owned(), "up".to_owned()),
            ("wg0".to_owned(), "unknown".to_owned()),
            ("eth1".to_owned(), "down".to_owned()),
        ];
        assert_eq!(select_interfaces(&entries), vec!["eth0", "wg0"]);
    }

    #[test]
    fn node_name_is_non_empty() {
        assert_ne!(node_name(), "");
    }
}
