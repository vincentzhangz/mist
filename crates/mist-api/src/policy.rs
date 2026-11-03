//! Per-workload `NetworkPolicy` recommendations from observed flows.
//!
//! Scope: external traffic only. Each response carries one policy per
//! workload (pods sharing the same selector labels) with `ipBlock` rules
//! for the external endpoints that workload talked to, plus a namespace
//! default-deny-all. Selector labels are the pod's labels minus
//! `pod-template-hash`, which changes every rollout and would silently
//! unmatch. Other cluster-internal peers are reported as names only, not
//! selectors — except DNS: queries a workload sends to internal port 53
//! earn a UDP+TCP allow per workload (namespace+pod selector when the
//! server pod was attributed, else an `ipBlock` fallback), so the
//! default-deny doesn't break name resolution.
//!
//! Pods with external traffic but no usable labels can't be targeted by
//! any safe `podSelector`, so they are listed as uncovered instead of
//! getting rules; the default-deny would block them, which the YAML
//! comments call out explicitly.
//!
//! Reply traffic needs no rules (conntrack allows it back): flows where the
//! local side sits on an ephemeral port (`>= 32768`) are skipped, as are
//! internal remotes and protocols Kubernetes can't express (`TCP`/`UDP`/
//! `SCTP` only). A namespace with no observed external traffic gets a
//! single explicit deny-all policy, clearly commented.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::net::IpAddr;

use mist_types::{FlowRecord, PodRef, TrafficDirection};
use serde::Serialize;

/// Local ports at or above this are treated as ephemeral (reply traffic).
const EPHEMERAL_PORT_MIN: u16 = 32_768;

/// DNS port. Queries to internal port 53 get a carve-out so the
/// default-deny doesn't break name resolution.
const DNS_PORT: u16 = 53;

/// Well-known label Kubernetes stamps on every namespace (stable since
/// 1.21); the only way a `namespaceSelector` can match by name.
const NAMESPACE_NAME_LABEL: &str = "kubernetes.io/metadata.name";

/// One allowed destination port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PortRule {
    pub port: u16,
    /// Uppercase `TCP` / `UDP` / `SCTP`, as Kubernetes expects.
    pub protocol: String,
}

/// One allowed remote: a `/32` (or `/128`) plus its observed ports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CidrRule {
    pub cidr: String,
    pub ports: Vec<PortRule>,
}

/// One workload's slice of the recommendation: the pods it covers, the
/// `matchLabels` selector targeting them, and their external rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WorkloadPolicy {
    /// Unique policy base name (`{workload}-observed`, suffixed on clash).
    pub workload: String,
    /// Selector labels shared by the covered pods (sorted).
    pub selector: BTreeMap<String, String>,
    /// Covered pod names (sorted).
    pub pods: Vec<String>,
    pub external_egress: Vec<CidrRule>,
    pub external_ingress: Vec<CidrRule>,
    /// DNS egress allows (UDP+TCP 53), selector- or ipBlock-targeted.
    pub dns_egress: Vec<DnsRule>,
}

/// One DNS egress allow. Selector-targeted when the server pod was
/// attributed (`namespace` + `pod_selector`); otherwise an `ipBlock`
/// fallback (`cidr`) that needs re-checking after pod churn.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DnsRule {
    /// Server namespace when the server pod was attributed.
    pub namespace: Option<String>,
    /// Server pod selector (empty for `ipBlock` rules).
    pub pod_selector: BTreeMap<String, String>,
    /// `/32` (or `/128`) fallback when the server was unattributed.
    pub cidr: Option<String>,
    /// Observed server IPs behind this rule (sorted).
    pub servers: Vec<String>,
}

/// A pod with external traffic that got no rules: no usable labels means
/// no safe `podSelector`, so the default-deny would block it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UncoveredPod {
    pub pod: String,
    pub reason: String,
}

/// Full recommendation for one namespace, including ready-to-review YAML.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Recommendation {
    pub namespace: String,
    pub flows_analyzed: usize,
    /// Flows to internal remotes other than DNS (no rule possible).
    pub internal_flows: usize,
    /// Internal DNS queries (carved out as egress allows per workload).
    pub dns_flows: usize,
    /// Flows with protocols Kubernetes can't express.
    pub unsupported_flows: usize,
    /// Local workload names observed (name-prefix heuristic).
    pub workloads: Vec<String>,
    /// Union of all workload egress rules (kept for summary views).
    pub external_egress: Vec<CidrRule>,
    /// Union of all workload ingress rules (kept for summary views).
    pub external_ingress: Vec<CidrRule>,
    /// Per-workload policies, sorted by policy name.
    pub workload_policies: Vec<WorkloadPolicy>,
    /// Pods with external traffic but no usable labels (sorted by pod).
    pub uncovered: Vec<UncoveredPod>,
    pub yaml: String,
}

/// Owning workload guess from a pod name: strip the last `-segment`
/// (pod hash or `StatefulSet` ordinal). `web-0` → `web`,
/// `web-7f9c4d6b5d-x2kq4` → `web-7f9c4d6b5d` (stable per rollout).
#[must_use]
pub fn workload_of(pod_name: &str) -> &str {
    pod_name
        .rsplit_once('-')
        .filter(|(prefix, _)| !prefix.is_empty())
        .map_or(pod_name, |(prefix, _)| prefix)
}

/// Kubernetes protocol name, or `None` when unrepresentable.
fn k8s_protocol(protocol: u8) -> Option<&'static str> {
    match protocol {
        6 => Some("TCP"),
        17 => Some("UDP"),
        132 => Some("SCTP"),
        _ => None,
    }
}

fn cidr_of(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(_) => format!("{ip}/32"),
        IpAddr::V6(_) => format!("{ip}/128"),
    }
}

type PortSet = BTreeSet<(u16, String)>;

/// Label excluded from selectors: it changes on every rollout, so a
/// `matchLabels` pinning it would silently unmatch after the next deploy.
const SELECTOR_EXCLUDE_LABEL: &str = "pod-template-hash";

/// Outcome of classifying one flow for policy purposes.
enum Verdict<'a> {
    /// No local side, reply traffic, or sensor-direction mismatch.
    Skip,
    /// Remote is cluster-internal: counted, never ruled.
    Internal,
    /// Query to internal DNS: carved out as an egress allow.
    DnsQuery {
        local: &'a PodRef,
        server_ip: IpAddr,
        server_pod: Option<&'a PodRef>,
    },
    /// Protocol Kubernetes can't express: counted, never ruled.
    Unsupported,
    /// External + supported: eligible for an `ipBlock` rule.
    Rule {
        local: &'a PodRef,
        cidr: String,
        port: u16,
        protocol: &'static str,
        egress: bool,
    },
}

/// Classify one flow: find the local side, drop replies and mismatches,
/// and split internal/unsupported from rule-eligible traffic.
fn classify<'a>(
    flow: &'a FlowRecord,
    namespace: &str,
    internal_cidrs: &[(u32, u8)],
) -> Verdict<'a> {
    // Local side first: src in-namespace means the workload reached
    // out (egress); dst in-namespace means it was reached (ingress).
    let local_src = flow
        .src_pod
        .as_ref()
        .is_some_and(|pod| pod.namespace == namespace);
    let local_dst = flow
        .dst_pod
        .as_ref()
        .is_some_and(|pod| pod.namespace == namespace);
    let (local, remote_ip, remote_port, local_port, is_egress) = if local_src {
        (
            flow.src_pod.as_ref(),
            &flow.key.dst_ip,
            flow.key.dst_port,
            flow.key.src_port,
            true,
        )
    } else if local_dst {
        (
            flow.dst_pod.as_ref(),
            &flow.key.src_ip,
            flow.key.src_port,
            flow.key.dst_port,
            false,
        )
    } else {
        return Verdict::Skip;
    };
    // `local_src`/`local_dst` just proved the pod is present.
    let Some(local) = local else {
        return Verdict::Skip;
    };
    // Replies ride back through conntrack; only service ports define
    // ingress policy.
    if !is_egress && local_port >= EPHEMERAL_PORT_MIN {
        return Verdict::Skip;
    }
    // Sensor-direction cross-check: an "egress" verdict on an ingress
    // capture (or vice versa) is reply traffic wearing the other key.
    let sensor_egress = flow.direction == TrafficDirection::Egress;
    if sensor_egress != is_egress {
        return Verdict::Skip;
    }
    if crate::analyzer::is_internal(remote_ip, internal_cidrs) {
        // Queries the workload sends to internal DNS earn a carve-out;
        // anything else internal is counted and left alone.
        if is_egress && remote_port == DNS_PORT && matches!(flow.key.protocol, 6 | 17) {
            return Verdict::DnsQuery {
                local,
                server_ip: *remote_ip,
                server_pod: flow.dst_pod.as_ref(),
            };
        }
        return Verdict::Internal;
    }
    let Some(protocol) = k8s_protocol(flow.key.protocol) else {
        return Verdict::Unsupported;
    };
    // Egress rules pin the remote port; ingress rules pin the local one.
    Verdict::Rule {
        local,
        cidr: cidr_of(remote_ip),
        port: if is_egress { remote_port } else { local_port },
        protocol,
        egress: is_egress,
    }
}

/// Selector labels for a pod: all labels minus rollout-unstable ones,
/// as sorted pairs (fit for grouping keys and `matchLabels`).
fn selector_of(pod: &PodRef) -> SelectorPairs {
    let mut pairs: Vec<(String, String)> = pod
        .labels
        .iter()
        .filter(|(key, _)| key.as_str() != SELECTOR_EXCLUDE_LABEL)
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    pairs.sort();
    pairs
}

/// Sorted label pairs: grouping key and `matchLabels` source.
type SelectorPairs = Vec<(String, String)>;

/// Server namespace + selector pairs: DNS selector-rule key.
type DnsSelectorKey = (String, SelectorPairs);

/// Per-workload accumulation: covered pods plus their rule tables.
#[derive(Default)]
struct WorkloadAcc {
    pods: BTreeSet<String>,
    egress: BTreeMap<String, PortSet>,
    ingress: BTreeMap<String, PortSet>,
    dns: DnsAcc,
}

/// Observed DNS servers: selector-keyed ones plus bare IPs.
#[derive(Default)]
struct DnsAcc {
    selectors: BTreeMap<DnsSelectorKey, BTreeSet<IpAddr>>,
    /// Server IPs whose pod was unattributed (or unselectable).
    ips: BTreeSet<IpAddr>,
}

/// Record a pod that had rule-eligible traffic but no usable selector.
fn mark_uncovered(uncovered: &mut BTreeMap<String, String>, pod: &PodRef) {
    uncovered.entry(pod.name.clone()).or_insert_with(|| {
        if pod.labels.is_empty() {
            "pod has no labels; no podSelector can target it".to_owned()
        } else {
            format!("only {SELECTOR_EXCLUDE_LABEL} label; excluded as rollout-unstable")
        }
    });
}

/// Fold one DNS query into its workload's DNS accumulation. The server
/// lands in the selector table when attributed with usable labels, else
/// in the bare-IP fallback set.
fn record_dns(
    groups: &mut BTreeMap<SelectorPairs, WorkloadAcc>,
    uncovered: &mut BTreeMap<String, String>,
    local: &PodRef,
    server_ip: IpAddr,
    server_pod: Option<&PodRef>,
) {
    let selector = selector_of(local);
    if selector.is_empty() {
        mark_uncovered(uncovered, local);
        return;
    }
    let acc = groups.entry(selector).or_default();
    acc.pods.insert(local.name.clone());
    let keyed = server_pod.and_then(|server| {
        if server.namespace.is_empty() {
            return None;
        }
        let selector = selector_of(server);
        (!selector.is_empty()).then(|| (server.namespace.clone(), selector))
    });
    match keyed {
        Some(key) => {
            acc.dns.selectors.entry(key).or_default().insert(server_ip);
        }
        None => {
            acc.dns.ips.insert(server_ip);
        }
    }
}

/// Flatten a CIDR→ports table into sorted rules.
fn collect_rules(table: &BTreeMap<String, PortSet>) -> Vec<CidrRule> {
    table
        .iter()
        .map(|(cidr, ports)| CidrRule {
            cidr: cidr.clone(),
            ports: ports
                .iter()
                .map(|(port, protocol)| PortRule {
                    port: *port,
                    protocol: protocol.clone(),
                })
                .collect(),
        })
        .collect::<Vec<_>>()
}

/// Flatten DNS accumulation into sorted allows: selector-targeted
/// rules first, then one `ipBlock` rule per bare server IP.
fn collect_dns(dns: &DnsAcc) -> Vec<DnsRule> {
    let mut rules = Vec::with_capacity(dns.selectors.len() + dns.ips.len());
    for ((namespace, selector), servers) in &dns.selectors {
        rules.push(DnsRule {
            namespace: Some(namespace.clone()),
            pod_selector: selector.iter().cloned().collect(),
            cidr: None,
            servers: servers.iter().map(IpAddr::to_string).collect(),
        });
    }
    for ip in &dns.ips {
        rules.push(DnsRule {
            namespace: None,
            pod_selector: BTreeMap::new(),
            cidr: Some(cidr_of(ip)),
            servers: vec![ip.to_string()],
        });
    }
    rules
}

/// Turn grouped accumulations into named workload policies, sorted by
/// policy name. Names derive from the alphabetically-first pod and gain
/// a numeric suffix when two label-sets share a name prefix.
fn finalize_policies(groups: &BTreeMap<SelectorPairs, WorkloadAcc>) -> Vec<WorkloadPolicy> {
    let mut policies: Vec<WorkloadPolicy> = Vec::with_capacity(groups.len());
    let mut used_names: BTreeSet<String> = BTreeSet::new();
    for (selector, acc) in groups {
        let base = acc
            .pods
            .iter()
            .next()
            .map_or("workload", |pod| workload_of(pod));
        let mut name = format!("{base}-observed");
        let mut suffix = 2;
        while !used_names.insert(name.clone()) {
            name = format!("{base}-observed-{suffix}");
            suffix += 1;
        }
        policies.push(WorkloadPolicy {
            workload: name,
            selector: selector.iter().cloned().collect(),
            pods: acc.pods.iter().cloned().collect(),
            external_egress: collect_rules(&acc.egress),
            external_ingress: collect_rules(&acc.ingress),
            dns_egress: collect_dns(&acc.dns),
        });
    }
    policies.sort_by(|a, b| a.workload.cmp(&b.workload));
    policies
}

/// Recommend namespace policies from its observed flows.
/// `internal_cidrs` uses the analyzer's `(network, prefix_len)` form.
#[must_use]
pub fn recommend(
    flows: &[FlowRecord],
    namespace: &str,
    internal_cidrs: &[(u32, u8)],
) -> Recommendation {
    let mut union_egress: BTreeMap<String, PortSet> = BTreeMap::new();
    let mut union_ingress: BTreeMap<String, PortSet> = BTreeMap::new();
    let mut workloads = BTreeSet::new();
    let mut groups: BTreeMap<SelectorPairs, WorkloadAcc> = BTreeMap::new();
    let mut uncovered: BTreeMap<String, String> = BTreeMap::new();
    let mut internal_flows = 0_usize;
    let mut dns_flows = 0_usize;
    let mut unsupported_flows = 0_usize;

    for flow in flows {
        for pod in [&flow.src_pod, &flow.dst_pod].into_iter().flatten() {
            if pod.namespace == namespace {
                workloads.insert(workload_of(&pod.name).to_owned());
            }
        }
        match classify(flow, namespace, internal_cidrs) {
            Verdict::Skip => {}
            Verdict::Internal => internal_flows += 1,
            Verdict::Unsupported => unsupported_flows += 1,
            Verdict::DnsQuery {
                local,
                server_ip,
                server_pod,
            } => {
                dns_flows += 1;
                record_dns(&mut groups, &mut uncovered, local, server_ip, server_pod);
            }
            Verdict::Rule {
                local,
                cidr,
                port,
                protocol,
                egress,
            } => {
                let union = if egress {
                    &mut union_egress
                } else {
                    &mut union_ingress
                };
                union
                    .entry(cidr.clone())
                    .or_default()
                    .insert((port, protocol.to_owned()));
                let selector = selector_of(local);
                if selector.is_empty() {
                    mark_uncovered(&mut uncovered, local);
                } else {
                    let acc = groups.entry(selector).or_default();
                    acc.pods.insert(local.name.clone());
                    let table = if egress {
                        &mut acc.egress
                    } else {
                        &mut acc.ingress
                    };
                    table
                        .entry(cidr)
                        .or_default()
                        .insert((port, protocol.to_owned()));
                }
            }
        }
    }

    let external_egress = collect_rules(&union_egress);
    let external_ingress = collect_rules(&union_ingress);
    let workload_policies = finalize_policies(&groups);
    let uncovered: Vec<UncoveredPod> = uncovered
        .into_iter()
        .map(|(pod, reason)| UncoveredPod { pod, reason })
        .collect();
    let yaml = render_yaml(
        namespace,
        &workload_policies,
        &uncovered,
        flows.len(),
        internal_flows,
        dns_flows,
        unsupported_flows,
    );
    Recommendation {
        namespace: namespace.to_owned(),
        flows_analyzed: flows.len(),
        internal_flows,
        dns_flows,
        unsupported_flows,
        workloads: workloads.into_iter().collect(),
        external_egress,
        external_ingress,
        workload_policies,
        uncovered,
        yaml,
    }
}

fn render_rules(rules: &[CidrRule], egress: bool) -> String {
    // Ingress peers use `from:`; egress targets use `to:`.
    let peer = if egress { "to" } else { "from" };
    let mut out = String::new();
    for rule in rules {
        let _ = writeln!(out, "  - {peer}:");
        out.push_str("    - ipBlock:\n");
        let _ = writeln!(out, "        cidr: {}", rule.cidr);
        out.push_str("    ports:\n");
        for port in &rule.ports {
            let _ = writeln!(out, "    - port: {}", port.port);
            let _ = writeln!(out, "      protocol: {}", port.protocol);
        }
    }
    out
}

/// Render DNS egress allows: UDP+TCP 53 to each observed server, the
/// namespace+pod selector when attributed, else an `ipBlock` fallback.
fn render_dns_rules(rules: &[DnsRule]) -> String {
    let mut out = String::new();
    for rule in rules {
        let servers = rule.servers.join(", ");
        match (&rule.namespace, &rule.cidr) {
            (Some(ns), _) => {
                let _ = writeln!(out, "  # DNS queries to {servers}: allow UDP+TCP 53");
                out.push_str("  - to:\n    - namespaceSelector:\n        matchLabels:\n");
                let _ = writeln!(out, "          {NAMESPACE_NAME_LABEL}: \"{ns}\"");
                out.push_str("      podSelector:\n        matchLabels:\n");
                for (key, value) in &rule.pod_selector {
                    let _ = writeln!(out, "          {key}: \"{value}\"");
                }
            }
            (None, Some(cidr)) => {
                let _ = writeln!(
                    out,
                    "  # DNS queries to unattributed {servers}: \
                     ipBlock, re-check after pod churn"
                );
                out.push_str("  - to:\n    - ipBlock:\n");
                let _ = writeln!(out, "        cidr: {cidr}");
            }
            // Unreachable: collection always sets one target. Skip rather
            // than emitting a rule with no peer.
            (None, None) => continue,
        }
        out.push_str(
            "    ports:\n    - port: 53\n      protocol: UDP\n    - port: 53\n      protocol: TCP\n",
        );
    }
    out
}

/// Render one policy document. `selector` is `None` for the covering-all
/// default-deny and `Some` `matchLabels` for a workload policy. Empty
/// rule lists are emitted as explicit deny-all (`[]`) with a comment.
fn render_policy_doc(
    name: &str,
    namespace: &str,
    selector: Option<&BTreeMap<String, String>>,
    egress: &[CidrRule],
    ingress: &[CidrRule],
    dns: &[DnsRule],
) -> String {
    let mut out = format!(
        "apiVersion: networking.k8s.io/v1\n\
         kind: NetworkPolicy\n\
         metadata:\n\
         \x20 name: {name}\n\
         \x20 namespace: {namespace}\n\
         \x20 annotations:\n\
         \x20\x20\x20\x20mist.managed-by: mist-recommender\n\
         spec:\n"
    );
    match selector {
        None => out.push_str("  podSelector: {}\n"),
        Some(labels) => {
            out.push_str("  podSelector:\n    matchLabels:\n");
            // Values are quoted: label values may be plain digits, which
            // YAML would otherwise read as numbers.
            for (key, value) in labels {
                let _ = writeln!(out, "      {key}: \"{value}\"");
            }
        }
    }
    out.push_str("  policyTypes:\n  - Egress\n  - Ingress\n");
    if dns.is_empty() && egress.is_empty() {
        out.push_str("  # no external egress observed: empty list denies all\n");
        out.push_str("  egress: []\n");
    } else {
        out.push_str("  egress:\n");
        out.push_str(&render_dns_rules(dns));
        out.push_str(&render_rules(egress, true));
    }
    if ingress.is_empty() {
        out.push_str("  # no external ingress observed: empty list denies all\n");
        out.push_str("  ingress: []\n");
    } else {
        out.push_str("  ingress:\n");
        out.push_str(&render_rules(ingress, false));
    }
    out
}

/// Render the full recommendation: one document per workload plus a
/// namespace default-deny-all, or a single deny-all when no workload
/// has external traffic.
fn render_yaml(
    namespace: &str,
    policies: &[WorkloadPolicy],
    uncovered: &[UncoveredPod],
    flows: usize,
    internal: usize,
    dns: usize,
    unsupported: usize,
) -> String {
    let mut out = format!(
        "# Generated by mist from {flows} observed flows \
         ({internal} internal-only, {dns} DNS, {unsupported} unsupported-protocol skipped).\n"
    );
    if policies.is_empty() {
        out.push_str("# No workload with external traffic: single deny-all below.\n");
    } else {
        let noun = if policies.len() == 1 {
            "policy"
        } else {
            "policies"
        };
        let _ = writeln!(
            out,
            "# {} workload {noun} + default-deny-all. Review before applying.",
            policies.len()
        );
    }
    out.push_str(
        "# NOTE: empty rule lists also block pod-to-pod traffic; observed\n\
         # DNS queries are carved out per covered workload only.\n",
    );
    if !uncovered.is_empty() {
        out.push_str(
            "# Uncovered pods (external traffic seen, no usable labels;\n\
             # the default-deny will block them — label them or add manual rules):\n",
        );
        for pod in uncovered {
            let _ = writeln!(out, "# - {}: {}", pod.pod, pod.reason);
        }
    }
    if policies.is_empty() {
        out.push_str(&render_policy_doc(
            &format!("{namespace}-observed"),
            namespace,
            None,
            &[],
            &[],
            &[],
        ));
        return out;
    }
    for (index, policy) in policies.iter().enumerate() {
        if index > 0 {
            out.push_str("---\n");
        }
        out.push_str(&render_policy_doc(
            &policy.workload,
            namespace,
            Some(&policy.selector),
            &policy.external_egress,
            &policy.external_ingress,
            &policy.dns_egress,
        ));
    }
    out.push_str("---\n");
    out.push_str(&render_policy_doc(
        &format!("{namespace}-default-deny-all"),
        namespace,
        None,
        &[],
        &[],
        &[],
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use mist_types::FlowKey;
    use mist_types::PodRef;
    use std::collections::HashMap;
    use std::net::Ipv6Addr;

    const ANY: [(u32, u8); 0] = [];

    fn flow(
        src: (&str, u16, Option<&str>),
        dst: (&str, u16, Option<&str>),
        protocol: u8,
        direction: TrafficDirection,
    ) -> FlowRecord {
        // `ns/name` overrides the namespace; plain names stay in `default`.
        let pod = |name: Option<&str>| {
            name.map(|name| {
                let (namespace, name) = name.split_once('/').unwrap_or(("default", name));
                PodRef {
                    namespace: namespace.to_owned(),
                    name: name.to_owned(),
                    labels: HashMap::new(),
                }
            })
        };
        FlowRecord {
            key: FlowKey {
                src_ip: IpAddr::V4(src.0.parse().unwrap()),
                src_port: src.1,
                dst_ip: IpAddr::V4(dst.0.parse().unwrap()),
                dst_port: dst.1,
                protocol,
            },
            direction,
            bytes: 100,
            packets: 1,
            start_unix_ms: 0,
            last_seen_unix_ms: 0,
            node: "node-1".to_owned(),
            src_pod: pod(src.2),
            dst_pod: pod(dst.2),
        }
    }

    /// Stamp `labels` on both attributed pods of a fixture flow. Fixture
    /// flows have at most one local pod, so this targets it exactly.
    fn with_labels(record: FlowRecord, labels: &[(&str, &str)]) -> FlowRecord {
        with_side_labels(record, labels, labels)
    }

    /// Stamp different labels on each side (e.g. workload + DNS server).
    fn with_side_labels(
        mut record: FlowRecord,
        src: &[(&str, &str)],
        dst: &[(&str, &str)],
    ) -> FlowRecord {
        let stamp = |pod: &mut Option<PodRef>, labels: &[(&str, &str)]| {
            if let Some(pod) = pod {
                pod.labels = labels
                    .iter()
                    .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                    .collect();
            }
        };
        stamp(&mut record.src_pod, src);
        stamp(&mut record.dst_pod, dst);
        record
    }

    fn internal_cidrs() -> Vec<(u32, u8)> {
        ["10.0.0.0/8"]
            .into_iter()
            .filter_map(crate::analyzer::parse_cidr)
            .collect()
    }

    #[test]
    fn workload_strips_last_segment() {
        assert_eq!(workload_of("web-0"), "web");
        assert_eq!(workload_of("web-7f9c4d6b5d-x2kq4"), "web-7f9c4d6b5d");
        assert_eq!(workload_of("web"), "web");
        assert_eq!(workload_of("-x"), "-x");
    }

    #[test]
    fn egress_groups_ports_per_cidr_and_dedupes() {
        let flows = vec![
            flow(
                ("10.0.0.5", 54321, Some("web-0")),
                ("8.8.8.8", 53, None),
                17,
                TrafficDirection::Egress,
            ),
            flow(
                ("10.0.0.5", 54322, Some("web-0")),
                ("8.8.8.8", 443, None),
                6,
                TrafficDirection::Egress,
            ),
            flow(
                ("10.0.0.5", 54321, Some("web-0")),
                ("8.8.8.8", 53, None),
                17,
                TrafficDirection::Egress,
            ),
        ];
        let rec = recommend(&flows, "default", &internal_cidrs());
        assert_eq!(rec.flows_analyzed, 3);
        assert_eq!(rec.workloads, vec!["web".to_owned()]);
        assert_eq!(
            rec.external_egress,
            vec![CidrRule {
                cidr: "8.8.8.8/32".to_owned(),
                ports: vec![
                    PortRule {
                        port: 53,
                        protocol: "UDP".to_owned(),
                    },
                    PortRule {
                        port: 443,
                        protocol: "TCP".to_owned(),
                    },
                ],
            }]
        );
        assert_eq!(rec.external_ingress, Vec::new());
    }

    #[test]
    fn ingress_pins_service_port_and_skips_replies() {
        let flows = vec![
            // Incoming connection to a service port: rule.
            flow(
                ("1.1.1.1", 4444, None),
                ("10.0.0.5", 443, Some("web-0")),
                6,
                TrafficDirection::Ingress,
            ),
            // Reply to an outbound connection: conntrack covers it.
            flow(
                ("8.8.8.8", 53, None),
                ("10.0.0.5", 54321, Some("web-0")),
                17,
                TrafficDirection::Ingress,
            ),
            // Egress-hook reply wearing the reverse key: skipped.
            flow(
                ("8.8.8.8", 53, None),
                ("10.0.0.5", 443, Some("web-0")),
                17,
                TrafficDirection::Egress,
            ),
        ];
        let rec = recommend(&flows, "default", &internal_cidrs());
        assert_eq!(
            rec.external_ingress,
            vec![CidrRule {
                cidr: "1.1.1.1/32".to_owned(),
                ports: vec![PortRule {
                    port: 443,
                    protocol: "TCP".to_owned(),
                }],
            }]
        );
        assert_eq!(rec.external_egress, Vec::new());
    }

    #[test]
    fn internal_and_unsupported_are_counted_not_ruled() {
        let flows = vec![
            flow(
                ("10.0.0.5", 54321, Some("web-0")),
                ("10.0.0.9", 5432, Some("db-0")),
                6,
                TrafficDirection::Egress,
            ),
            flow(
                ("10.0.0.5", 0, Some("web-0")),
                ("8.8.8.8", 0, None),
                1,
                TrafficDirection::Egress,
            ),
        ];
        let rec = recommend(&flows, "default", &internal_cidrs());
        assert_eq!(rec.internal_flows, 1);
        assert_eq!(rec.unsupported_flows, 1);
        assert_eq!(rec.external_egress, Vec::new());
        assert_eq!(rec.external_ingress, Vec::new());
        assert_eq!(rec.workloads, vec!["db".to_owned(), "web".to_owned()]);
    }

    #[test]
    fn other_namespaces_are_ignored() {
        let flows = vec![flow(
            ("10.0.1.5", 54321, Some("web-0")),
            ("8.8.8.8", 53, None),
            17,
            TrafficDirection::Egress,
        )];
        // Pods are attributed to "default" by the fixture; ask for "other".
        let rec = recommend(&flows, "other", &internal_cidrs());
        assert_eq!(rec.external_egress, Vec::new());
        assert_eq!(rec.workloads, Vec::<String>::new());
    }

    #[test]
    fn cidr_v6_uses_128() {
        assert_eq!(
            cidr_of(&IpAddr::V6(Ipv6Addr::LOCALHOST)),
            "::1/128".to_owned()
        );
    }

    #[test]
    fn empty_recommends_deny_all() {
        let rec = recommend(&[], "default", &ANY);
        assert!(rec.yaml.contains("egress: []"));
        assert!(rec.yaml.contains("ingress: []"));
        assert!(rec.yaml.contains("name: default-observed"));
    }

    #[test]
    fn golden_yaml_for_workload_and_deny_all() {
        let flows = vec![with_labels(
            flow(
                ("10.0.0.5", 54321, Some("web-0")),
                ("8.8.8.8", 53, None),
                17,
                TrafficDirection::Egress,
            ),
            &[("app", "web")],
        )];
        let rec = recommend(&flows, "default", &internal_cidrs());
        assert_eq!(rec.workload_policies.len(), 1);
        assert_eq!(rec.workload_policies[0].workload, "web-observed");
        assert_eq!(rec.uncovered.len(), 0);
        let expected = "# Generated by mist from 1 observed flows \
         (0 internal-only, 0 DNS, 0 unsupported-protocol skipped).\n\
         # 1 workload policy + default-deny-all. Review before applying.\n\
         # NOTE: empty rule lists also block pod-to-pod traffic; observed\n\
         # DNS queries are carved out per covered workload only.\n\
         apiVersion: networking.k8s.io/v1\n\
         kind: NetworkPolicy\n\
         metadata:\n\
         \x20 name: web-observed\n\
         \x20 namespace: default\n\
         \x20 annotations:\n\
         \x20\x20\x20\x20mist.managed-by: mist-recommender\n\
         spec:\n\
         \x20 podSelector:\n\
         \x20\x20\x20\x20matchLabels:\n\
         \x20\x20\x20\x20\x20\x20app: \"web\"\n\
         \x20 policyTypes:\n\
         \x20 - Egress\n\
         \x20 - Ingress\n\
         \x20 egress:\n\
         \x20 - to:\n\
         \x20\x20\x20\x20- ipBlock:\n\
         \x20\x20\x20\x20\x20\x20\x20\x20cidr: 8.8.8.8/32\n\
         \x20\x20\x20\x20ports:\n\
         \x20\x20\x20\x20- port: 53\n\
         \x20\x20\x20\x20\x20\x20protocol: UDP\n\
         \x20 # no external ingress observed: empty list denies all\n\
         \x20 ingress: []\n\
         ---\n\
         apiVersion: networking.k8s.io/v1\n\
         kind: NetworkPolicy\n\
         metadata:\n\
         \x20 name: default-default-deny-all\n\
         \x20 namespace: default\n\
         \x20 annotations:\n\
         \x20\x20\x20\x20mist.managed-by: mist-recommender\n\
         spec:\n\
         \x20 podSelector: {}\n\
         \x20 policyTypes:\n\
         \x20 - Egress\n\
         \x20 - Ingress\n\
         \x20 # no external egress observed: empty list denies all\n\
         \x20 egress: []\n\
         \x20 # no external ingress observed: empty list denies all\n\
         \x20 ingress: []\n";
        assert_eq!(rec.yaml, expected);
    }

    #[test]
    fn workloads_split_by_selector_labels() {
        let web = with_labels(
            flow(
                ("10.0.0.5", 54321, Some("web-0")),
                ("8.8.8.8", 53, None),
                17,
                TrafficDirection::Egress,
            ),
            &[("app", "web")],
        );
        // Second replica, same labels: same workload, both pods covered.
        let web_replica = with_labels(
            flow(
                ("10.0.0.6", 54321, Some("web-1")),
                ("8.8.8.8", 53, None),
                17,
                TrafficDirection::Egress,
            ),
            &[("app", "web")],
        );
        let api = with_labels(
            flow(
                ("10.0.0.7", 54321, Some("api-0")),
                ("1.1.1.1", 443, None),
                6,
                TrafficDirection::Egress,
            ),
            &[("app", "api"), ("tier", "backend")],
        );
        let rec = recommend(&[web, web_replica, api], "default", &internal_cidrs());
        assert_eq!(rec.workload_policies.len(), 2);
        // Sorted by policy name.
        assert_eq!(rec.workload_policies[0].workload, "api-observed");
        assert_eq!(
            rec.workload_policies[0].selector,
            BTreeMap::from([
                ("app".to_owned(), "api".to_owned()),
                ("tier".to_owned(), "backend".to_owned()),
            ])
        );
        assert_eq!(rec.workload_policies[0].pods, vec!["api-0".to_owned()]);
        assert_eq!(
            rec.workload_policies[0].external_egress[0].cidr,
            "1.1.1.1/32".to_owned()
        );
        assert_eq!(rec.workload_policies[1].workload, "web-observed");
        assert_eq!(
            rec.workload_policies[1].pods,
            vec!["web-0".to_owned(), "web-1".to_owned()]
        );
        // Union tables still carry every observed CIDR.
        assert_eq!(rec.external_egress.len(), 2);
        assert_eq!(rec.uncovered.len(), 0);
    }

    #[test]
    fn unlabeled_pods_are_uncovered_not_ruled() {
        let flows = vec![flow(
            ("10.0.0.5", 54321, Some("bare-0")),
            ("8.8.8.8", 53, None),
            17,
            TrafficDirection::Egress,
        )];
        let rec = recommend(&flows, "default", &internal_cidrs());
        assert_eq!(rec.workload_policies.len(), 0);
        assert_eq!(rec.uncovered.len(), 1);
        assert_eq!(rec.uncovered[0].pod, "bare-0");
        assert!(rec.uncovered[0].reason.contains("no labels"));
        // Union still observes the traffic; the YAML stays a single
        // deny-all plus the uncovered callout.
        assert_eq!(rec.external_egress.len(), 1);
        assert!(rec.yaml.contains("name: default-observed"));
        assert!(rec.yaml.contains("# - bare-0:"));
    }

    #[test]
    fn template_hash_is_excluded_from_selectors() {
        let only_hash = with_labels(
            flow(
                ("10.0.0.5", 54321, Some("web-0")),
                ("8.8.8.8", 53, None),
                17,
                TrafficDirection::Egress,
            ),
            &[("pod-template-hash", "7f9c4d6b5d")],
        );
        let rec = recommend(&[only_hash], "default", &internal_cidrs());
        assert_eq!(rec.workload_policies.len(), 0);
        assert_eq!(rec.uncovered.len(), 1);
        assert!(rec.uncovered[0].reason.contains("rollout-unstable"));

        let with_app = with_labels(
            flow(
                ("10.0.0.5", 54321, Some("web-0")),
                ("8.8.8.8", 53, None),
                17,
                TrafficDirection::Egress,
            ),
            &[("app", "web"), ("pod-template-hash", "7f9c4d6b5d")],
        );
        let rec = recommend(&[with_app], "default", &internal_cidrs());
        assert_eq!(rec.workload_policies.len(), 1);
        assert_eq!(
            rec.workload_policies[0].selector,
            BTreeMap::from([("app".to_owned(), "web".to_owned())])
        );
        assert!(!rec.yaml.contains("pod-template-hash"));
    }

    #[test]
    fn ingress_rules_use_from_peer() {
        let flows = vec![with_labels(
            flow(
                ("1.1.1.1", 4444, None),
                ("10.0.0.5", 443, Some("web-0")),
                6,
                TrafficDirection::Ingress,
            ),
            &[("app", "web")],
        )];
        let rec = recommend(&flows, "default", &internal_cidrs());
        assert_eq!(rec.workload_policies.len(), 1);
        assert_eq!(rec.workload_policies[0].external_ingress.len(), 1);
        assert!(rec.yaml.contains("  - from:\n"));
        assert!(!rec.yaml.contains("  - to:\n"));
    }

    #[test]
    fn dns_queries_get_selector_allows() {
        let flows = vec![with_side_labels(
            flow(
                ("10.0.0.5", 54321, Some("web-0")),
                ("10.96.0.10", 53, Some("kube-system/kube-dns")),
                17,
                TrafficDirection::Egress,
            ),
            &[("app", "web")],
            &[("k8s-app", "kube-dns")],
        )];
        let rec = recommend(&flows, "default", &internal_cidrs());
        assert_eq!(rec.dns_flows, 1);
        assert_eq!(rec.internal_flows, 0);
        assert_eq!(rec.workload_policies.len(), 1);
        let dns = &rec.workload_policies[0].dns_egress;
        assert_eq!(dns.len(), 1);
        assert_eq!(dns[0].namespace.as_deref(), Some("kube-system"));
        assert_eq!(
            dns[0].pod_selector,
            BTreeMap::from([("k8s-app".to_owned(), "kube-dns".to_owned())])
        );
        assert_eq!(dns[0].cidr, None);
        assert_eq!(dns[0].servers, vec!["10.96.0.10".to_owned()]);
        // No ipBlock rules: DNS-only workload still gets its policy doc.
        assert_eq!(rec.workload_policies[0].external_egress.len(), 0);
        assert!(rec.yaml.contains("namespaceSelector:"));
        assert!(rec.yaml.contains("podSelector:"));
        assert!(rec.yaml.contains("k8s-app: \"kube-dns\""));
        // Both transports allowed even though only UDP was observed.
        assert!(rec.yaml.contains("- port: 53\n      protocol: UDP"));
        assert!(rec.yaml.contains("- port: 53\n      protocol: TCP"));
    }

    #[test]
    fn unattributed_dns_falls_back_to_ipblock() {
        let bare = flow(
            ("10.0.0.5", 54321, Some("web-0")),
            ("10.96.0.10", 53, None),
            17,
            TrafficDirection::Egress,
        );
        let bare = with_labels(bare, &[("app", "web")]);
        // Attributed but unselectable server (hash-only labels): same path.
        let hash_only = with_side_labels(
            flow(
                ("10.0.0.5", 54322, Some("web-0")),
                ("10.96.0.11", 53, Some("kube-system/kube-dns-x")),
                17,
                TrafficDirection::Egress,
            ),
            &[("app", "web")],
            &[("pod-template-hash", "abc123")],
        );
        let rec = recommend(&[bare, hash_only], "default", &internal_cidrs());
        assert_eq!(rec.dns_flows, 2);
        let dns = &rec.workload_policies[0].dns_egress;
        assert_eq!(dns.len(), 2);
        assert!(dns.iter().all(|rule| rule.namespace.is_none()));
        assert_eq!(dns[0].cidr.as_deref(), Some("10.96.0.10/32"));
        assert_eq!(dns[1].cidr.as_deref(), Some("10.96.0.11/32"));
        assert!(rec.yaml.contains("cidr: 10.96.0.10/32"));
        assert!(rec.yaml.contains("re-check after pod churn"));
    }

    #[test]
    fn dns_from_unlabeled_pod_is_uncovered() {
        let flows = vec![flow(
            ("10.0.0.5", 54321, Some("bare-0")),
            ("10.96.0.10", 53, Some("kube-system/kube-dns")),
            17,
            TrafficDirection::Egress,
        )];
        let rec = recommend(&flows, "default", &internal_cidrs());
        assert_eq!(rec.dns_flows, 1);
        assert_eq!(rec.workload_policies.len(), 0);
        assert_eq!(rec.uncovered.len(), 1);
        assert_eq!(rec.uncovered[0].pod, "bare-0");
    }

    #[test]
    fn external_dns_stays_a_normal_egress_rule() {
        let flows = vec![with_labels(
            flow(
                ("10.0.0.5", 54321, Some("web-0")),
                ("8.8.8.8", 53, None),
                17,
                TrafficDirection::Egress,
            ),
            &[("app", "web")],
        )];
        let rec = recommend(&flows, "default", &internal_cidrs());
        assert_eq!(rec.dns_flows, 0);
        assert_eq!(rec.workload_policies[0].external_egress.len(), 1);
        assert_eq!(rec.workload_policies[0].dns_egress.len(), 0);
    }

    #[test]
    fn policy_names_dedupe_on_prefix_clash() {
        // Same name prefix, different label-sets: distinct workloads.
        let one = with_labels(
            flow(
                ("10.0.0.5", 54321, Some("red-x")),
                ("8.8.8.8", 53, None),
                17,
                TrafficDirection::Egress,
            ),
            &[("app", "one")],
        );
        let two = with_labels(
            flow(
                ("10.0.0.6", 54321, Some("red-y")),
                ("1.1.1.1", 443, None),
                6,
                TrafficDirection::Egress,
            ),
            &[("app", "two")],
        );
        let rec = recommend(&[one, two], "default", &internal_cidrs());
        let names: Vec<&str> = rec
            .workload_policies
            .iter()
            .map(|policy| policy.workload.as_str())
            .collect();
        assert_eq!(names, vec!["red-observed", "red-observed-2"]);
    }
}
