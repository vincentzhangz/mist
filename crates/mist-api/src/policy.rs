//! Namespace-wide `NetworkPolicy` recommendations from observed flows.
//!
//! v1 scope: external traffic only. Each response carries one policy per
//! namespace covering all its pods (`podSelector: {}`) with `ipBlock` rules
//! for the external endpoints the namespace talked to. Per-workload
//! scoping needs pod labels, which flows don't carry yet, and
//! cluster-internal peers are reported as names only, not selectors.
//!
//! Reply traffic needs no rules (conntrack allows it back): flows where the
//! local side sits on an ephemeral port (`>= 32768`) are skipped, as are
//! internal remotes and protocols Kubernetes can't express (`TCP`/`UDP`/
//! `SCTP` only). A namespace with no observed external traffic gets an
//! explicit deny-all policy, clearly commented.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::net::IpAddr;

use mist_types::{FlowRecord, TrafficDirection};
use serde::Serialize;

/// Local ports at or above this are treated as ephemeral (reply traffic).
const EPHEMERAL_PORT_MIN: u16 = 32_768;

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

/// Full recommendation for one namespace, including ready-to-review YAML.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Recommendation {
    pub namespace: String,
    pub flows_analyzed: usize,
    /// Flows to internal remotes (no `ipBlock` rule possible).
    pub internal_flows: usize,
    /// Flows with protocols Kubernetes can't express.
    pub unsupported_flows: usize,
    /// Local workload names observed (name-prefix heuristic).
    pub workloads: Vec<String>,
    pub external_egress: Vec<CidrRule>,
    pub external_ingress: Vec<CidrRule>,
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

/// Recommend a namespace policy from its observed flows. `internal_cidrs`
/// uses the analyzer's `(network, prefix_len)` form.
#[must_use]
pub fn recommend(
    flows: &[FlowRecord],
    namespace: &str,
    internal_cidrs: &[(u32, u8)],
) -> Recommendation {
    let mut egress: BTreeMap<String, PortSet> = BTreeMap::new();
    let mut ingress: BTreeMap<String, PortSet> = BTreeMap::new();
    let mut workloads = BTreeSet::new();
    let mut internal_flows = 0_usize;
    let mut unsupported_flows = 0_usize;

    for flow in flows {
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
        for pod in [&flow.src_pod, &flow.dst_pod].into_iter().flatten() {
            if pod.namespace == namespace {
                workloads.insert(workload_of(&pod.name).to_owned());
            }
        }
        let (remote_ip, remote_port, local_port, is_egress) = if local_src {
            (&flow.key.dst_ip, flow.key.dst_port, flow.key.src_port, true)
        } else if local_dst {
            (
                &flow.key.src_ip,
                flow.key.src_port,
                flow.key.dst_port,
                false,
            )
        } else {
            continue;
        };
        // Replies ride back through conntrack; only service ports define
        // ingress policy.
        if !is_egress && local_port >= EPHEMERAL_PORT_MIN {
            continue;
        }
        // Sensor-direction cross-check: an "egress" verdict on an ingress
        // capture (or vice versa) is reply traffic wearing the other key.
        let sensor_egress = flow.direction == TrafficDirection::Egress;
        if sensor_egress != is_egress {
            continue;
        }
        if crate::analyzer::is_internal(remote_ip, internal_cidrs) {
            internal_flows += 1;
            continue;
        }
        let Some(protocol) = k8s_protocol(flow.key.protocol) else {
            unsupported_flows += 1;
            continue;
        };
        // Egress rules pin the remote port; ingress rules pin the local one.
        let port = if is_egress { remote_port } else { local_port };
        let table = if is_egress { &mut egress } else { &mut ingress };
        table
            .entry(cidr_of(remote_ip))
            .or_default()
            .insert((port, protocol.to_owned()));
    }

    let collect = |table: BTreeMap<String, PortSet>| {
        table
            .into_iter()
            .map(|(cidr, ports)| CidrRule {
                cidr,
                ports: ports
                    .into_iter()
                    .map(|(port, protocol)| PortRule { port, protocol })
                    .collect(),
            })
            .collect::<Vec<_>>()
    };
    let external_egress = collect(egress);
    let external_ingress = collect(ingress);
    let yaml = render_yaml(
        namespace,
        &external_egress,
        &external_ingress,
        flows.len(),
        internal_flows,
        unsupported_flows,
    );
    Recommendation {
        namespace: namespace.to_owned(),
        flows_analyzed: flows.len(),
        internal_flows,
        unsupported_flows,
        workloads: workloads.into_iter().collect(),
        external_egress,
        external_ingress,
        yaml,
    }
}

fn render_rules(rules: &[CidrRule]) -> String {
    let mut out = String::new();
    for rule in rules {
        out.push_str("  - to:\n");
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

/// Render the namespace policy. Empty rule lists are emitted as explicit
/// deny-all (`[]`) with a comment saying what was (not) observed.
fn render_yaml(
    namespace: &str,
    egress: &[CidrRule],
    ingress: &[CidrRule],
    flows: usize,
    internal: usize,
    unsupported: usize,
) -> String {
    let mut out = format!(
        "# Generated by mist from {flows} observed flows \
         ({internal} internal-only, {unsupported} unsupported-protocol skipped).\n\
         # Scope: all pods in namespace \"{namespace}\" (podSelector: {{}});\n\
         # per-workload scoping needs pod labels. Review before applying.\n\
         apiVersion: networking.k8s.io/v1\n\
         kind: NetworkPolicy\n\
         metadata:\n\
         \x20 name: {namespace}-observed\n\
         \x20 namespace: {namespace}\n\
         \x20 annotations:\n\
         \x20\x20\x20\x20mist.managed-by: mist-recommender\n\
         spec:\n\
         \x20 podSelector: {{}}\n\
         \x20 policyTypes:\n\
         \x20 - Egress\n\
         \x20 - Ingress\n"
    );
    if egress.is_empty() {
        out.push_str("  # no external egress observed: empty list denies all\n");
        out.push_str("  egress: []\n");
    } else {
        out.push_str("  egress:\n");
        out.push_str(&render_rules(egress));
    }
    if ingress.is_empty() {
        out.push_str("  # no external ingress observed: empty list denies all\n");
        out.push_str("  ingress: []\n");
    } else {
        out.push_str("  ingress:\n");
        out.push_str(&render_rules(ingress));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use mist_types::FlowKey;
    use mist_types::PodRef;
    use std::net::Ipv6Addr;

    const ANY: [(u32, u8); 0] = [];

    fn flow(
        src: (&str, u16, Option<&str>),
        dst: (&str, u16, Option<&str>),
        protocol: u8,
        direction: TrafficDirection,
    ) -> FlowRecord {
        let pod = |name: Option<&str>| {
            name.map(|name| PodRef {
                namespace: "default".to_owned(),
                name: name.to_owned(),
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
    fn golden_yaml_for_mixed_traffic() {
        let flows = vec![flow(
            ("10.0.0.5", 54321, Some("web-0")),
            ("8.8.8.8", 53, None),
            17,
            TrafficDirection::Egress,
        )];
        let rec = recommend(&flows, "default", &internal_cidrs());
        let expected = "# Generated by mist from 1 observed flows \
         (0 internal-only, 0 unsupported-protocol skipped).\n\
         # Scope: all pods in namespace \"default\" (podSelector: {});\n\
         # per-workload scoping needs pod labels. Review before applying.\n\
         apiVersion: networking.k8s.io/v1\n\
         kind: NetworkPolicy\n\
         metadata:\n\
         \x20 name: default-observed\n\
         \x20 namespace: default\n\
         \x20 annotations:\n\
         \x20\x20\x20\x20mist.managed-by: mist-recommender\n\
         spec:\n\
         \x20 podSelector: {}\n\
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
         \x20 ingress: []\n";
        assert_eq!(rec.yaml, expected);
    }
}
