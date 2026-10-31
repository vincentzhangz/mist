//! Overview: cluster-wide stats, top talkers, and recent firing alerts.
//!
//! All numbers are computed client-side from the shared flow/alert signals,
//! which this view loads on mount and the websocket loop keeps patched.

use std::cmp::Reverse;
use std::collections::BTreeMap;

use leptos::prelude::*;

use crate::api::{fetch_alerts, fetch_flows};
use crate::dto::{AlertState, AlertView, Direction, FlowRecord, Severity};
use crate::state::{AppState, format_bytes};
use crate::views::alerts::severity_badge;
use crate::views::charts::{
    BarChart, TimeSeriesChart, bucket_series, bytes_by_direction, bytes_by_protocol,
};

/// Rows shown in the top-talkers and recent-alerts panels.
const PANEL_ROWS: usize = 5;

/// Buckets in the traffic-over-time chart.
const TIME_BUCKETS: usize = 24;

/// Pod attribution matching the flows table: egress counts the source pod,
/// ingress counts the destination pod.
fn flow_pod(flow: &FlowRecord) -> String {
    crate::state::pod_label(match flow.direction {
        Direction::Egress => flow.src_pod.as_ref(),
        Direction::Ingress => flow.dst_pod.as_ref(),
    })
}

/// Top `n` pods by total bytes, descending: `(pod, bytes, flow_count)`.
///
/// Unattributed flows (`—`) are skipped so the panel only names real pods.
#[must_use]
pub fn top_talkers(flows: &[FlowRecord], n: usize) -> Vec<(String, u64, usize)> {
    let mut totals: BTreeMap<String, (u64, usize)> = BTreeMap::new();
    for flow in flows {
        let pod = flow_pod(flow);
        if pod == "—" {
            continue;
        }
        let entry = totals.entry(pod).or_insert((0, 0));
        entry.0 += flow.bytes;
        entry.1 += 1;
    }
    let mut ranked: Vec<(String, u64, usize)> = totals
        .into_iter()
        .map(|(pod, (bytes, count))| (pod, bytes, count))
        .collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    ranked.truncate(n);
    ranked
}

/// Firing alert counts by severity: `(info, warning, critical)`.
#[must_use]
pub fn firing_by_severity(alerts: &[AlertView]) -> (usize, usize, usize) {
    let mut counts = (0, 0, 0);
    for alert in alerts.iter().filter(|a| a.state == AlertState::Firing) {
        match alert.severity {
            Severity::Info => counts.0 += 1,
            Severity::Warning => counts.1 += 1,
            Severity::Critical => counts.2 += 1,
        }
    }
    counts
}

/// Most recently seen firing alerts, newest first, capped at `n`.
#[must_use]
pub fn recent_firing(alerts: &[AlertView], n: usize) -> Vec<AlertView> {
    let mut firing: Vec<&AlertView> = alerts
        .iter()
        .filter(|a| a.state == AlertState::Firing)
        .collect();
    firing.sort_by_key(|a| Reverse(a.last_seen_unix_ms));
    firing.into_iter().take(n).cloned().collect()
}

/// Overview landing page: stat cards plus top talkers and recent alerts.
#[component]
pub fn OverviewView() -> impl IntoView {
    let state = expect_context::<AppState>();
    let loading = RwSignal::new(true);
    let error = RwSignal::new(Option::<String>::None);

    // Load both signals (also refreshed live by the shell's WS loop).
    Effect::new(move || {
        let Some(token) = state.token.get() else {
            return;
        };
        loading.set(true);
        let session = state;
        leptos::task::spawn_local(async move {
            match fetch_flows(&token, 500).await {
                Ok(flows) => {
                    session.flows.set(flows);
                    error.set(None);
                }
                Err(err) => {
                    session.logout_if_unauthorized(&err);
                    error.set(Some(err.to_string()));
                }
            }
            match fetch_alerts(&token, Some("firing"), None, 200).await {
                Ok(alerts) => {
                    session.alerts.set(alerts);
                }
                Err(err) => {
                    session.logout_if_unauthorized(&err);
                    error.set(Some(err.to_string()));
                }
            }
            loading.set(false);
        });
    });

    view! {
        <section class="overview">
            <h2>"Overview"</h2>
            <Show when=move || error.get().is_some()>
                <p class="error" aria-live="polite">
                    {move || error.get().unwrap_or_default()}
                </p>
            </Show>
            <Show
                when=move || !loading.get()
                fallback=|| view! { <p class="muted">"Loading overview…"</p> }
            >
                <StatCards state=state />
                <TrafficPanel state=state />
                <div class="overview-grid">
                    <ProtocolPanel state=state />
                    <DirectionPanel state=state />
                </div>
                <div class="overview-grid">
                    <TopTalkersPanel state=state />
                    <RecentAlertsPanel state=state />
                </div>
            </Show>
        </section>
    }
}

/// Four stat cards computed from the shared flow/alert signals.
#[component]
fn StatCards(state: AppState) -> impl IntoView {
    let total_bytes = move || state.flows.get().iter().map(|f| f.bytes).sum::<u64>();
    let total_packets = move || state.flows.get().iter().map(|f| f.packets).sum::<u64>();
    let firing_total = move || {
        let (info, warning, critical) = firing_by_severity(&state.alerts.get());
        info + warning + critical
    };
    view! {
        <div class="stats">
            <div class="stat">
                <span class="stat-value">{move || state.flows.get().len().to_string()}</span>
                <span class="stat-label">"Flows tracked"</span>
            </div>
            <div class="stat">
                <span class="stat-value">{move || format_bytes(total_bytes())}</span>
                <span class="stat-label">"Bytes observed"</span>
            </div>
            <div class="stat">
                <span class="stat-value">{move || total_packets().to_string()}</span>
                <span class="stat-label">"Packets observed"</span>
            </div>
            <div class="stat">
                <span class="stat-value">{move || firing_total().to_string()}</span>
                <span class="stat-label">
                    {move || {
                        let (info, warning, critical) = firing_by_severity(&state.alerts.get());
                        format!(
                            "Firing · {critical} critical · {warning} warning · {info} info",
                        )
                    }}
                </span>
            </div>
        </div>
    }
}

/// Traffic-over-time chart, from the shared flow signal.
#[component]
fn TrafficPanel(state: AppState) -> impl IntoView {
    view! {
        <div class="chart-panel">
            <h3>"Traffic over time"</h3>
            {move || {
                let series = bucket_series(&state.flows.get(), TIME_BUCKETS);
                view! { <TimeSeriesChart series=series /> }
            }}
        </div>
    }
}

/// Bytes-by-protocol chart, from the shared flow signal.
#[component]
fn ProtocolPanel(state: AppState) -> impl IntoView {
    view! {
        <div>
            <h3>"Bytes by protocol"</h3>
            {move || view! { <BarChart data={bytes_by_protocol(&state.flows.get())} /> }}
        </div>
    }
}

/// Ingress-vs-egress chart, from the shared flow signal.
#[component]
fn DirectionPanel(state: AppState) -> impl IntoView {
    view! {
        <div>
            <h3>"Ingress vs egress"</h3>
            {move || {
                let (ingress, egress) = bytes_by_direction(&state.flows.get());
                view! {
                    <BarChart data=vec![
                        ("ingress".to_owned(), ingress),
                        ("egress".to_owned(), egress),
                    ] />
                }
            }}
        </div>
    }
}

/// Top pods by bytes, from the shared flow signal.
#[component]
fn TopTalkersPanel(state: AppState) -> impl IntoView {
    view! {
        <div>
            <h3>"Top talkers"</h3>
            <Show
                when=move || !top_talkers(&state.flows.get(), PANEL_ROWS).is_empty()
                fallback=|| view! { <p class="muted">"No attributed flows yet."</p> }
            >
                <table>
                    <thead>
                        <tr>
                            <th>"Pod"</th>
                            <th class="num">"Bytes"</th>
                            <th class="num">"Flows"</th>
                        </tr>
                    </thead>
                    <tbody>
                        <For
                            each=move || top_talkers(&state.flows.get(), PANEL_ROWS)
                            key=|(pod, _, _)| pod.clone()
                            let(row)
                        >
                            <tr>
                                <td class="mono">{row.0.clone()}</td>
                                <td class="num">{format_bytes(row.1)}</td>
                                <td class="num">{row.2.to_string()}</td>
                            </tr>
                        </For>
                    </tbody>
                </table>
            </Show>
        </div>
    }
}

/// Most recent firing alerts, from the shared alert signal.
#[component]
fn RecentAlertsPanel(state: AppState) -> impl IntoView {
    view! {
        <div>
            <h3>"Recent firing alerts"</h3>
            <Show
                when=move || !recent_firing(&state.alerts.get(), PANEL_ROWS).is_empty()
                fallback=|| view! { <p class="muted">"Nothing firing."</p> }
            >
                <ul class="recent-alerts">
                    <For
                        each=move || recent_firing(&state.alerts.get(), PANEL_ROWS)
                        key=|alert| alert.id.clone()
                        let(alert)
                    >
                        {
                            let (sev_label, sev_class) = severity_badge(alert.severity);
                            view! {
                                <li>
                                    <span class=format!("sev {sev_class}")>{sev_label}</span>
                                    <span class="alert-title">{alert.title.clone()}</span>
                                    <span class="alert-state">
                                        {crate::state::format_time_ms(alert.last_seen_unix_ms)}
                                    </span>
                                </li>
                            }
                        }
                    </For>
                </ul>
            </Show>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::{FlowKey, PodRef};

    fn flow(pod: Option<&str>, bytes: u64, direction: Direction) -> FlowRecord {
        let pod_ref = pod.map(|name| PodRef {
            namespace: "default".to_owned(),
            name: name.to_owned(),
        });
        let (src_pod, dst_pod) = match direction {
            Direction::Egress => (pod_ref, None),
            Direction::Ingress => (None, pod_ref),
        };
        FlowRecord {
            key: FlowKey {
                src_ip: "10.0.0.1".to_owned(),
                src_port: 1,
                dst_ip: "10.0.0.2".to_owned(),
                dst_port: 2,
                protocol: 6,
            },
            direction,
            bytes,
            packets: 1,
            start_unix_ms: 0,
            last_seen_unix_ms: 0,
            node: "node-1".to_owned(),
            src_pod,
            dst_pod,
        }
    }

    fn alert(id: &str, severity: Severity, state: AlertState, last_seen: u64) -> AlertView {
        AlertView {
            id: id.to_owned(),
            severity,
            title: id.to_owned(),
            detail: String::new(),
            first_seen_unix_ms: 0,
            last_seen_unix_ms: last_seen,
            labels: BTreeMap::new(),
            explanation: None,
            state,
            occurrences: 1,
        }
    }

    #[test]
    fn talkers_rank_by_bytes_and_skip_unattributed() {
        let flows = vec![
            flow(Some("web-0"), 100, Direction::Egress),
            flow(Some("web-0"), 200, Direction::Egress),
            flow(Some("db-0"), 1_000, Direction::Ingress),
            flow(None, 9_999, Direction::Egress),
        ];
        assert_eq!(
            top_talkers(&flows, 5),
            vec![
                ("default/db-0".to_owned(), 1_000, 1),
                ("default/web-0".to_owned(), 300, 2),
            ]
        );
        assert_eq!(top_talkers(&flows, 1).len(), 1);
        assert_eq!(top_talkers(&[], 5).len(), 0);
    }

    #[test]
    fn firing_counts_ignore_resolved() {
        let alerts = vec![
            alert("a", Severity::Critical, AlertState::Firing, 3),
            alert("b", Severity::Warning, AlertState::Firing, 2),
            alert("c", Severity::Info, AlertState::Firing, 1),
            alert("d", Severity::Critical, AlertState::Resolved, 4),
        ];
        assert_eq!(firing_by_severity(&alerts), (1, 1, 1));
        let recent = recent_firing(&alerts, 5);
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].id, "a");
        assert_eq!(recent[2].id, "c");
        assert_eq!(recent_firing(&alerts, 2).len(), 2);
    }
}
