//! Linux loader: attach TC classifiers, drain maps, ship batches.

use std::{
    borrow::{Borrow, BorrowMut},
    collections::{HashMap, HashSet},
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

use crate::Args;
use crate::convert;

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
                    // `ObjectMeta.labels` is a `BTreeMap`; flows carry a `HashMap`.
                    let labels: HashMap<String, String> = pod
                        .metadata
                        .labels
                        .clone()
                        .unwrap_or_default()
                        .into_iter()
                        .collect();
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
                                    labels: labels.clone(),
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

    let auto_detect = args.iface.is_empty();
    let ifaces = if auto_detect {
        detect_interfaces()
    } else {
        args.iface.clone()
    };
    anyhow::ensure!(!ifaces.is_empty(), "no network interfaces to attach to");
    attach_interfaces(&mut bpf, &ifaces)?;
    let mut attached: HashSet<String> = ifaces.into_iter().collect();
    let mut last_rescan = Instant::now();

    // `take_map` moves each map out of `bpf`, so the two handles are owned
    // instead of borrowing `bpf` across each other (two `map_mut` borrows
    // won't compile).
    let mut flows = PerCpuHashMap::<_, Key, Stats>::try_from(
        bpf.take_map("FLOWS").context("finding FLOWS map")?,
    )?;
    let stats_map =
        PerCpuArray::<_, u64>::try_from(bpf.take_map("STATS").context("finding STATS map")?)?;
    let tls = crate::tls::load_tls_materials(args)?;
    let http = crate::tls::build_http_client(tls.ca_pem.as_deref(), tls.identity_pem.as_deref())
        .context("building HTTP client")?;
    let ingest_url = format!("{}/api/ingest", args.api_url.trim_end_matches('/'));

    let mut pods = PodCache::new().await;
    let mut ticker = tokio::time::interval(Duration::from_secs(args.interval_secs));
    loop {
        ticker.tick().await;
        pods.refresh_if_stale().await;
        // Pods (and their veths) churn constantly; without a rescan any
        // pod created after startup is invisible to the sensor.
        if auto_detect && last_rescan.elapsed() >= Duration::from_secs(30) {
            last_rescan = Instant::now();
            let current = detect_interfaces();
            let new = convert::unattached_interfaces(&current, &attached);
            if !new.is_empty() {
                attach_new_interfaces(&mut bpf, &new);
                attached.extend(new);
            }
            attached.retain(|iface| current.contains(iface));
        }
        let mut batch = drain(&mut flows, &node, &pods.entries)?;
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
        // Always ship, even when idle: the empty batch is this node's
        // heartbeat, and it carries the eBPF pressure counters.
        batch.updated = updated;
        batch.skipped = skipped;
        batch.map_full = map_full;
        let mut request = http.post(&ingest_url);
        if !args.api_token.is_empty() {
            request = request.bearer_auth(&args.api_token);
        }
        match request.json(&batch).send().await {
            Ok(response) if response.status().is_success() => {}
            Ok(response) => tracing::warn!(
                status = %response.status(),
                url = %ingest_url,
                "ingest shipment rejected"
            ),
            Err(error) => {
                tracing::warn!(?error, url = %ingest_url, "ingest shipment failed");
            }
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
        updated: 0,
        skipped: 0,
        map_full: 0,
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

/// Attach the already-loaded classifiers to rescanned interfaces.
/// Best-effort per interface (a veth can vanish mid-scan); failures log
/// and the next rescan retries.
fn attach_new_interfaces(bpf: &mut Ebpf, ifaces: &[String]) {
    for (prog_name, attach_type) in [
        ("mist_ingress", TcAttachType::Ingress),
        ("mist_egress", TcAttachType::Egress),
    ] {
        let program: Option<&mut SchedClassifier> = bpf
            .program_mut(prog_name)
            .and_then(|program| program.try_into().ok());
        let Some(program) = program else {
            tracing::warn!(prog = prog_name, "rescan found no loaded program");
            continue;
        };
        for iface in ifaces {
            let attached = CString::new(iface.as_str())
                .map_err(|error| anyhow::anyhow!("{error}"))
                .and_then(|iface_c| {
                    // Idempotent: present qdiscs error, which we ignore.
                    let _ = tc::qdisc_add_clsact(iface_c.as_c_str());
                    program
                        .attach(iface_c.as_c_str(), attach_type)
                        .map_err(anyhow::Error::from)
                });
            match attached {
                Ok(_) => {
                    tracing::info!(prog = prog_name, iface, "attached classifier (rescan)");
                }
                Err(error) => {
                    tracing::warn!(?error, prog = prog_name, iface, "rescan attach failed");
                }
            }
        }
    }
}
