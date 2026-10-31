//! Hand-rolled SVG charts: bar chart + time series, no dependencies.
//!
//! Geometry is computed with integer math into `viewBox` coordinates so the
//! SVG scales to its container; the pure layout helpers are unit-tested.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use leptos::prelude::*;

use crate::dto::{Direction, FlowRecord, protocol_name};
use crate::state::{format_bytes, format_time_ms};

/// Total bytes per protocol name, descending.
#[must_use]
pub fn bytes_by_protocol(flows: &[FlowRecord]) -> Vec<(String, u64)> {
    let mut totals: BTreeMap<String, u64> = BTreeMap::new();
    for flow in flows {
        *totals.entry(protocol_name(flow.key.protocol)).or_insert(0) += flow.bytes;
    }
    let mut ranked: Vec<(String, u64)> = totals.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    ranked
}

/// `(ingress_bytes, egress_bytes)` totals.
#[must_use]
pub fn bytes_by_direction(flows: &[FlowRecord]) -> (u64, u64) {
    let mut totals = (0, 0);
    for flow in flows {
        match flow.direction {
            Direction::Ingress => totals.0 += flow.bytes,
            Direction::Egress => totals.1 += flow.bytes,
        }
    }
    totals
}

/// Flow bytes bucketed over the observed `[min, max]` last-seen window.
pub struct TimeSeries {
    /// Clock label of the first bucket edge.
    pub start: String,
    /// Clock label of the last bucket edge.
    pub end: String,
    /// Bytes per bucket, oldest first.
    pub buckets: Vec<u64>,
}

/// Bucket flow bytes into `n` time buckets spanning the observed last-seen
/// window. Empty input (or `n == 0`) yields empty buckets.
#[must_use]
pub fn bucket_series(flows: &[FlowRecord], n: usize) -> TimeSeries {
    let empty = || TimeSeries {
        start: String::new(),
        end: String::new(),
        buckets: Vec::new(),
    };
    if flows.is_empty() || n == 0 {
        return empty();
    }
    let min = flows.iter().map(|f| f.last_seen_unix_ms).min().unwrap_or(0);
    let max = flows.iter().map(|f| f.last_seen_unix_ms).max().unwrap_or(0);
    let mut buckets = vec![0_u64; n];
    if min == max {
        buckets[n - 1] = flows.iter().map(|f| f.bytes).sum();
    } else {
        let span = max - min;
        for flow in flows {
            let quotient = (flow.last_seen_unix_ms - min) * n as u64 / span;
            let idx = usize::try_from(quotient).unwrap_or(usize::MAX).min(n - 1);
            buckets[idx] += flow.bytes;
        }
    }
    TimeSeries {
        start: format_time_ms(min),
        end: format_time_ms(max),
        buckets,
    }
}

// --- bar chart ---------------------------------------------------------------

const BAR_W: u64 = 400;
const BAR_H: u64 = 170;
const BAR_TOP: u64 = 18;
const BAR_LABEL_H: u64 = 22;
const BAR_PLOT_H: u64 = BAR_H - BAR_TOP - BAR_LABEL_H;

/// One laid-out bar: `viewBox` rect plus label/value strings.
#[derive(Debug, Clone)]
pub struct Bar {
    pub x: u64,
    pub y: u64,
    pub w: u64,
    pub h: u64,
    pub label: String,
    pub value: String,
}

/// Lay out bars for `(label, bytes)` pairs. Empty input yields no bars.
#[must_use]
pub fn layout_bars(data: &[(String, u64)]) -> Vec<Bar> {
    let max = data.iter().map(|(_, v)| *v).max().unwrap_or(0);
    if data.is_empty() || max == 0 {
        return Vec::new();
    }
    let n = data.len() as u64;
    let slot = BAR_W / n;
    let bar_w = (slot * 3 / 5).max(2);
    let step = max / BAR_PLOT_H + 1;
    data.iter()
        .zip(0..)
        .map(|((label, bytes), i)| {
            let h = if *bytes == 0 {
                0
            } else {
                (bytes / step).clamp(1, BAR_PLOT_H)
            };
            Bar {
                x: i * slot + (slot - bar_w) / 2,
                y: BAR_TOP + BAR_PLOT_H - h,
                w: bar_w,
                h,
                label: label.clone(),
                value: format_bytes(*bytes),
            }
        })
        .collect()
}

/// Bar chart for `(label, bytes)` pairs.
#[component]
#[allow(clippy::needless_pass_by_value)]
pub fn BarChart(data: Vec<(String, u64)>) -> impl IntoView {
    let bars = layout_bars(&data);
    if bars.is_empty() {
        return view! { <p class="muted">"No data yet."</p> }.into_any();
    }
    view! {
        <svg
            class="chart"
            viewBox=format!("0 0 {BAR_W} {BAR_H}")
            role="img"
        >
            <For each=move || bars.clone() key=|bar| bar.label.clone() let(bar)>
                <rect
                    class="bar"
                    x=bar.x.to_string()
                    y=bar.y.to_string()
                    width=bar.w.to_string()
                    height=bar.h.max(1).to_string()
                />
                <text
                    x=(bar.x + bar.w / 2).to_string()
                    y=bar.y.saturating_sub(4).to_string()
                    text-anchor="middle"
                >
                    {bar.value.clone()}
                </text>
                <text
                    x=(bar.x + bar.w / 2).to_string()
                    y=(BAR_H - 6).to_string()
                    text-anchor="middle"
                >
                    {bar.label.clone()}
                </text>
            </For>
        </svg>
    }
    .into_any()
}

// --- time series --------------------------------------------------------------

const SERIES_W: u64 = 600;
const SERIES_H: u64 = 170;
const SERIES_TOP: u64 = 18;
const SERIES_LABEL_H: u64 = 20;
const SERIES_PLOT_H: u64 = SERIES_H - SERIES_TOP - SERIES_LABEL_H;

/// Laid-out polyline points, area polygon, and peak value.
pub struct SeriesGeom {
    pub points: String,
    pub area: String,
    pub peak: u64,
}

/// Lay out a series polyline. Returns `None` when there is nothing to draw
/// (fewer than two buckets or all zeros).
#[must_use]
pub fn layout_series(buckets: &[u64]) -> Option<SeriesGeom> {
    let max = buckets.iter().copied().max().unwrap_or(0);
    if buckets.len() < 2 || max == 0 {
        return None;
    }
    let n = buckets.len() as u64;
    let step = max / SERIES_PLOT_H + 1;
    let base = SERIES_TOP + SERIES_PLOT_H;
    let mut points = String::new();
    for (value, i) in buckets.iter().zip(0..) {
        let x = i * SERIES_W / (n - 1);
        let h = (value / step).min(SERIES_PLOT_H);
        let _ = write!(points, "{x},{} ", base - h);
    }
    let first_x = 0;
    let last_x = SERIES_W;
    Some(SeriesGeom {
        points: points.trim_end().to_owned(),
        area: format!("{first_x},{base} {} {last_x},{base}", points.trim_end()),
        peak: max,
    })
}

/// Time-series area chart for bucketed bytes.
#[component]
#[allow(clippy::needless_pass_by_value)]
pub fn TimeSeriesChart(series: TimeSeries) -> impl IntoView {
    let Some(geom) = layout_series(&series.buckets) else {
        return view! { <p class="muted">"No data yet."</p> }.into_any();
    };
    view! {
        <svg
            class="chart"
            viewBox=format!("0 0 {SERIES_W} {SERIES_H}")
            role="img"
        >
            <polygon class="area" points=geom.area.clone() />
            <polyline class="line" points=geom.points.clone() />
            <text x="0" y="10">
                {format!("peak {}", format_bytes(geom.peak))}
            </text>
            <text x="0" y=(SERIES_H - 4).to_string()>
                {series.start.clone()}
            </text>
            <text x=SERIES_W.to_string() y=(SERIES_H - 4).to_string() text-anchor="end">
                {series.end.clone()}
            </text>
        </svg>
    }
    .into_any()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(bytes: u64, protocol: u8, direction: &str, last_seen: u64) -> FlowRecord {
        serde_json::from_str(&format!(
            r#"{{
                "key": {{"src_ip":"10.0.0.1","src_port":1,"dst_ip":"10.0.0.2","dst_port":2,"protocol":{protocol}}},
                "direction": "{direction}",
                "bytes": {bytes},
                "packets": 1,
                "start_unix_ms": 0,
                "last_seen_unix_ms": {last_seen},
                "node": "node-1",
                "src_pod": null,
                "dst_pod": null
            }}"#,
        ))
        .expect("fixture must parse")
    }

    #[test]
    fn protocol_totals_rank_descending() {
        let flows = vec![
            flow(100, 6, "egress", 0),
            flow(200, 6, "egress", 0),
            flow(500, 17, "ingress", 0),
            flow(10, 1, "ingress", 0),
        ];
        assert_eq!(
            bytes_by_protocol(&flows),
            vec![
                ("udp".to_owned(), 500),
                ("tcp".to_owned(), 300),
                ("icmp".to_owned(), 10),
            ]
        );
        assert_eq!(bytes_by_protocol(&[]), Vec::new());
    }

    #[test]
    fn direction_totals_split() {
        let flows = vec![flow(100, 6, "egress", 0), flow(50, 6, "ingress", 0)];
        assert_eq!(bytes_by_direction(&flows), (50, 100));
        assert_eq!(bytes_by_direction(&[]), (0, 0));
    }

    #[test]
    fn series_buckets_span_window() {
        // t=0 -> bucket 0, t=50 -> bucket 2, t=100 -> bucket 4.
        let flows = vec![
            flow(10, 6, "egress", 0),
            flow(20, 6, "egress", 50),
            flow(30, 6, "egress", 100),
        ];
        let series = bucket_series(&flows, 5);
        assert_eq!(series.buckets, vec![10, 0, 20, 0, 30]);
        assert_eq!(series.start, format_time_ms(0));
        assert_eq!(series.end, format_time_ms(100));
    }

    #[test]
    fn series_single_timestamp_lands_in_last_bucket() {
        let flows = vec![flow(10, 6, "egress", 7), flow(20, 6, "egress", 7)];
        let series = bucket_series(&flows, 4);
        assert_eq!(series.buckets, vec![0, 0, 0, 30]);
    }

    #[test]
    fn series_empty_input_has_no_buckets() {
        let series = bucket_series(&[], 8);
        assert_eq!(series.buckets, Vec::<u64>::new());
        assert_eq!(
            bucket_series(&[flow(1, 6, "egress", 0)], 0).buckets,
            Vec::<u64>::new()
        );
    }

    #[test]
    fn bars_scale_proportionally_within_plot() {
        let bars = layout_bars(&[("a".to_owned(), 1300), ("b".to_owned(), 650)]);
        assert_eq!(bars.len(), 2);
        assert!(bars[0].h <= BAR_PLOT_H);
        assert_eq!(bars[0].h, bars[1].h * 2);
        assert!(bars[0].x < bars[1].x);
        assert_eq!(bars[0].value, "1.2 KB");
        assert_eq!(layout_bars(&[]).len(), 0);
        assert_eq!(layout_bars(&[("z".to_owned(), 0)]).len(), 0);
    }

    #[test]
    fn series_layout_needs_two_nonzero_buckets() {
        assert!(layout_series(&[]).is_none());
        assert!(layout_series(&[5]).is_none());
        assert!(layout_series(&[0, 0, 0]).is_none());
        let geom = layout_series(&[0, 10, 0]).expect("must lay out");
        assert_eq!(geom.peak, 10);
        assert_eq!(geom.points, "0,150 300,140 600,150");
        assert_eq!(geom.area, "0,150 0,150 300,140 600,150 600,150");
    }
}
