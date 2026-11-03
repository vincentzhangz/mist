//! Wire conversion: fold eBPF per-CPU counters into API flow records,
//! plus interface-selection helpers shared with the loader.

use std::{
    collections::{HashMap, HashSet},
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

/// Interfaces in `current` that have no program attached yet. The agent
/// polls this on a timer: pod churn constantly creates veths that the
/// startup scan never saw, and their traffic is invisible until attach.
#[must_use]
pub fn unattached_interfaces(current: &[String], attached: &HashSet<String>) -> Vec<String> {
    current
        .iter()
        .filter(|name| !attached.contains(name.as_str()))
        .cloned()
        .collect()
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

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use mist_flow::{FlowKeyWire, FlowStatsWire};

    use super::*;

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
                labels: std::collections::HashMap::from([("app".to_owned(), "api".to_owned())]),
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
        assert_eq!(
            record
                .src_pod
                .as_ref()
                .unwrap()
                .labels
                .get("app")
                .map(String::as_str),
            Some("api")
        );
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

    #[test]
    fn rescan_finds_only_new_interfaces() {
        use std::collections::HashSet;

        let attached: HashSet<String> = ["eth0", "veth-old"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        // Steady state: nothing new.
        let current = vec!["eth0".to_owned(), "veth-old".to_owned()];
        assert_eq!(
            unattached_interfaces(&current, &attached),
            Vec::<String>::new()
        );
        // Pod churn: one new veth appears, one disappears (vanished ones
        // are simply dropped from the set; their programs die with them).
        let current = vec!["eth0".to_owned(), "veth-new".to_owned()];
        assert_eq!(
            unattached_interfaces(&current, &attached),
            vec!["veth-new".to_owned()]
        );
    }
}
