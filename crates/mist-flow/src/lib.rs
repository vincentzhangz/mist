//! Wire-level flow types and packet parser shared by the eBPF program and
//! the agent. `core`-only so it compiles for `bpfel-unknown-none`.
//!
//! # Panic-freedom
//! This code is linked into the eBPF program, where any panic path becomes a
//! trap stub that breaks program loading. All parsing uses [`Option`]
//! combinators over checked slices: no indexing, no `unwrap`, and no
//! arithmetic that can overflow in debug builds.

#![cfg_attr(not(test), no_std)]

/// Ethernet + IPv4 flow identity. All multi-byte fields hold network-byte-order
/// values converted with `from_be_bytes`, so the numeric value is identical in
/// the kernel map and userspace. 16 bytes, stable layout for BPF maps.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FlowKeyWire {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub direction: u8,
    pub pad: [u8; 2],
}

/// Per-flow counters, one copy per CPU in the kernel map. 40 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowStatsWire {
    pub packets: u64,
    pub bytes: u64,
    /// First observation, `CLOCK_MONOTONIC` nanoseconds.
    pub start_ns: u64,
    /// Most recent observation, `CLOCK_MONOTONIC` nanoseconds.
    pub last_ns: u64,
    /// Bitwise OR of observed TCP flags (0 for UDP and other protocols).
    pub tcp_flags: u8,
    pub pad: [u8; 7],
}

impl FlowStatsWire {
    /// Zero value for fresh map entries.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            packets: 0,
            bytes: 0,
            start_ns: 0,
            last_ns: 0,
            tcp_flags: 0,
            pad: [0; 7],
        }
    }
}

/// Capture direction of a flow.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Direction {
    Ingress = 0,
    Egress = 1,
}

impl Direction {
    /// Numeric encoding stored in [`FlowKeyWire::direction`].
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Ingress => 0,
            Self::Egress => 1,
        }
    }
}

/// Parsed packet summary: the map key plus the values to account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParsedFlow {
    pub key: FlowKeyWire,
    /// IPv4 total length: bytes accounted to this flow.
    pub bytes: u64,
    pub tcp_flags: u8,
}

pub const ETH_TYPE_IPV4: u16 = 0x0800;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

const ETH_HEADER_LEN: usize = 14;
const IPV4_MIN_HEADER_LEN: usize = 20;

/// Parse one Ethernet-framed packet into a flow key.
///
/// Returns `None` for truncated packets, non-IPv4 ethertypes, malformed IP
/// headers, and truncated TCP/UDP headers. Non-TCP/UDP protocols are recorded
/// with zero ports. Never panics.
#[must_use]
pub fn parse_ipv4_flow(packet: &[u8], direction: Direction) -> Option<ParsedFlow> {
    let ethertype = u16::from_be_bytes([*packet.get(12)?, *packet.get(13)?]);
    if ethertype != ETH_TYPE_IPV4 {
        return None;
    }
    let ip = packet.get(ETH_HEADER_LEN..)?;
    let version_ihl = *ip.first()?;
    if version_ihl >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(version_ihl & 0x0f).checked_mul(4)?;
    if ihl < IPV4_MIN_HEADER_LEN {
        return None;
    }
    let header = ip.get(..ihl)?;
    let total_len = u16::from_be_bytes([*header.get(2)?, *header.get(3)?]);
    if usize::from(total_len) < ihl {
        return None;
    }
    let protocol = *header.get(9)?;
    let src_ip = u32::from_be_bytes([
        *header.get(12)?,
        *header.get(13)?,
        *header.get(14)?,
        *header.get(15)?,
    ]);
    let dst_ip = u32::from_be_bytes([
        *header.get(16)?,
        *header.get(17)?,
        *header.get(18)?,
        *header.get(19)?,
    ]);
    let l4 = ip.get(ihl..)?;
    let (src_port, dst_port, tcp_flags) = match protocol {
        PROTO_TCP => {
            let flags = *l4.get(13)?;
            (
                u16::from_be_bytes([*l4.first()?, *l4.get(1)?]),
                u16::from_be_bytes([*l4.get(2)?, *l4.get(3)?]),
                flags,
            )
        }
        PROTO_UDP => (
            u16::from_be_bytes([*l4.first()?, *l4.get(1)?]),
            u16::from_be_bytes([*l4.get(2)?, *l4.get(3)?]),
            0,
        ),
        _ => (0, 0, 0),
    };
    Some(ParsedFlow {
        key: FlowKeyWire {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            direction: direction.as_u8(),
            pad: [0; 2],
        },
        bytes: u64::from(total_len),
        tcp_flags,
    })
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use super::*;

    /// Ethernet + IPv4 + payload skeleton. `l4` is the full L4 header.
    fn packet(protocol: u8, l4: &[u8]) -> Vec<u8> {
        let total_len = u16::try_from(IPV4_MIN_HEADER_LEN + l4.len()).unwrap();
        let total = total_len.to_be_bytes();
        let mut pkt = vec![0u8; ETH_HEADER_LEN];
        // Ethertype IPv4.
        pkt[12] = 0x08;
        pkt[13] = 0x00;
        // IPv4 header: version+ihl, DSCP/ECN, total len, id, flags/frag,
        // ttl, protocol, checksum, src 10.0.1.4, dst 10.0.2.9.
        pkt.extend_from_slice(&[
            0x45, 0x00, total[0], total[1], 0x00, 0x01, 0x40, 0x00, 64, protocol, 0x00, 0x00, 10,
            0, 1, 4, 10, 0, 2, 9,
        ]);
        pkt.extend_from_slice(l4);
        pkt
    }

    fn tcp_syn() -> Vec<u8> {
        // sport 51234, dport 443, seq/ack 0, dataofs 5, flags SYN.
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&51234u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = 0x02;
        packet(PROTO_TCP, &tcp)
    }

    #[test]
    fn wire_layout_is_stable() {
        assert_eq!(size_of::<FlowKeyWire>(), 16);
        assert_eq!(size_of::<FlowStatsWire>(), 40);
    }

    #[test]
    fn parses_tcp_packet() {
        let pkt = tcp_syn();
        let parsed = parse_ipv4_flow(&pkt, Direction::Ingress).unwrap();
        assert_eq!(
            parsed.key,
            FlowKeyWire {
                src_ip: u32::from_be_bytes([10, 0, 1, 4]),
                dst_ip: u32::from_be_bytes([10, 0, 2, 9]),
                src_port: 51234,
                dst_port: 443,
                protocol: PROTO_TCP,
                direction: 0,
                pad: [0; 2],
            }
        );
        assert_eq!(parsed.bytes, 40);
        assert_eq!(parsed.tcp_flags, 0x02);
    }

    #[test]
    fn parses_udp_packet() {
        let mut udp = vec![0u8; 8];
        udp[0..2].copy_from_slice(&53u16.to_be_bytes());
        udp[2..4].copy_from_slice(&5353u16.to_be_bytes());
        let pkt = packet(PROTO_UDP, &udp);
        let parsed = parse_ipv4_flow(&pkt, Direction::Egress).unwrap();
        assert_eq!(parsed.key.src_port, 53);
        assert_eq!(parsed.key.dst_port, 5353);
        assert_eq!(parsed.key.direction, 1);
        assert_eq!(parsed.tcp_flags, 0);
        assert_eq!(parsed.bytes, 28);
    }

    #[test]
    fn other_protocols_get_zero_ports() {
        let pkt = packet(1, &[0u8; 8]); // ICMP.
        let parsed = parse_ipv4_flow(&pkt, Direction::Ingress).unwrap();
        assert_eq!(parsed.key.protocol, 1);
        assert_eq!(parsed.key.src_port, 0);
        assert_eq!(parsed.key.dst_port, 0);
    }

    #[test]
    fn rejects_truncated_and_foreign_packets() {
        let pkt = tcp_syn();
        // Truncated frame.
        assert!(parse_ipv4_flow(&pkt[..10], Direction::Ingress).is_none());
        // Truncated TCP header (flags byte at index 47 missing).
        assert!(parse_ipv4_flow(&pkt[..47], Direction::Ingress).is_none());
        // Non-IPv4 ethertype (ARP).
        let mut arp = pkt.clone();
        arp[12] = 0x08;
        arp[13] = 0x06;
        assert!(parse_ipv4_flow(&arp, Direction::Ingress).is_none());
        // IPv6 version nibble.
        let mut v6 = pkt.clone();
        v6[14] = 0x65;
        assert!(parse_ipv4_flow(&v6, Direction::Ingress).is_none());
        // IHL below minimum.
        let mut bad_ihl = pkt.clone();
        bad_ihl[14] = 0x44;
        assert!(parse_ipv4_flow(&bad_ihl, Direction::Ingress).is_none());
    }
}
