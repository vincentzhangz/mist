#![no_std]
#![no_main]

//! mist eBPF flow sensor: TC ingress/egress classifiers that aggregate
//! per-flow counters (5-tuple + direction) in a per-CPU hash map.
//!
//! # Panic-freedom
//! eBPF programs cannot unwind: any panic path becomes a trap stub that makes
//! the program fail to load. All code here (and in `mist-flow`) avoids
//! panicking constructs: checked slices, `wrapping_*` arithmetic, and
//! unaligned map access instead of raw dereference (which emits alignment
//! checks in dev builds).

use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    helpers::{bpf_ktime_get_ns, bpf_skb_load_bytes},
    macros::{classifier, map},
    maps::{PerCpuArray, PerCpuHashMap},
    programs::TcContext,
    EbpfContext,
};
use mist_flow::{parse_ipv4_flow, Direction, FlowKeyWire, FlowStatsWire};

/// Per-CPU flow counters keyed by 5-tuple + direction. Drained periodically by
/// mist-agent (read + remove), which bounds growth without kernel-side LRU.
#[map]
static FLOWS: PerCpuHashMap<FlowKeyWire, FlowStatsWire> =
    PerCpuHashMap::with_max_entries(16_384, 0);

/// Operator counters: flows updated, packets skipped, map-full drops.
#[map]
static STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(3, 0);

const STAT_UPDATED: u32 = 0;
const STAT_SKIPPED: u32 = 1;
const STAT_MAP_FULL: u32 = 2;

/// Largest header span parsed: eth(14) + max IPv4 header(60) + TCP flags(14).
const LOAD_LEN: usize = 128;

/// `BPF_NOEXIST` from `linux/bpf.h`: fail insert if the key already exists, so
/// a concurrent first packet on another CPU is accounted via update instead of
/// being overwritten.
const BPF_NOEXIST: u64 = 1;

#[classifier]
pub fn mist_ingress(ctx: TcContext) -> i32 {
    track(&ctx, Direction::Ingress)
}

#[classifier]
pub fn mist_egress(ctx: TcContext) -> i32 {
    track(&ctx, Direction::Egress)
}

fn track(ctx: &TcContext, direction: Direction) -> i32 {
    if try_track(ctx, direction).is_err() {
        bump_stat(STAT_SKIPPED);
    }
    TC_ACT_PIPE
}

fn try_track(ctx: &TcContext, direction: Direction) -> Result<(), ()> {
    let mut buf = [0u8; LOAD_LEN];
    let want = (ctx.len() as usize).min(LOAD_LEN);
    // Zero-length reads are rejected by strict verifiers, so refuse them
    // before the helper call; aya's `load_bytes` wrapper lacks this guard.
    if want == 0 {
        return Err(());
    }
    // SAFETY: direct `bpf_skb_load_bytes` call: `buf` is a valid `want`-byte
    // stack destination, `want` is nonzero and within the packet.
    let ret = unsafe { bpf_skb_load_bytes(ctx.as_ptr(), 0, buf.as_mut_ptr().cast(), want as u32) };
    if ret != 0 {
        return Err(());
    }
    let packet = buf.get(..want).ok_or(())?;
    let parsed = parse_ipv4_flow(packet, direction).ok_or(())?;
    // SAFETY: `bpf_ktime_get_ns` takes no arguments and always succeeds.
    let now = unsafe { bpf_ktime_get_ns() };
    match FLOWS.get_ptr_mut(&parsed.key) {
        Some(value) => update_stats(value, &parsed, now),
        None => {
            let mut stats = FlowStatsWire::zero();
            stats.packets = 1;
            stats.bytes = parsed.bytes;
            stats.start_ns = now;
            stats.last_ns = now;
            stats.tcp_flags = parsed.tcp_flags;
            if FLOWS.insert(&parsed.key, &stats, BPF_NOEXIST).is_err() {
                // Either the map is full or another CPU won the race; retry
                // as an update before counting a drop.
                if let Some(value) = FLOWS.get_ptr_mut(&parsed.key) {
                    update_stats(value, &parsed, now);
                } else {
                    bump_stat(STAT_MAP_FULL);
                    return Err(());
                }
            }
        }
    }
    bump_stat(STAT_UPDATED);
    Ok(())
}

fn update_stats(value: *mut FlowStatsWire, parsed: &mist_flow::ParsedFlow, now: u64) {
    // SAFETY: `value` points to this CPU's initialized map value, written only
    // by this CPU. The unaligned copy avoids alignment checks on raw field
    // access, which would emit panic paths in dev builds.
    unsafe {
        let mut stats = value.read_unaligned();
        stats.packets = stats.packets.wrapping_add(1);
        stats.bytes = stats.bytes.wrapping_add(parsed.bytes);
        stats.last_ns = now;
        stats.tcp_flags |= parsed.tcp_flags;
        value.write_unaligned(stats);
    }
}

fn bump_stat(slot: u32) {
    if let Some(cell) = STATS.get_ptr_mut(slot) {
        // SAFETY: per-CPU counter slot, valid when the index is in range.
        unsafe {
            let value = cell.read_unaligned();
            cell.write_unaligned(value.wrapping_add(1));
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
