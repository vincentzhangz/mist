//! Flows view: REST snapshot + live WS prepend, capped rows.

use leptos::prelude::*;

use crate::api::fetch_flows;
use crate::dto::{Direction, FlowRecord, protocol_name};
use crate::state::{AppState, format_time_ms, pod_label};

/// Snapshot sizes offered by the flows limit control.
const FLOW_LIMITS: [usize; 3] = [100, 200, 500];

/// Whether a flow's display fields contain the (already lowercased) query.
fn flow_matches(flow: &FlowRecord, query: &str) -> bool {
    if query.is_empty() {
        return true;
    }
    let direction = match flow.direction {
        Direction::Egress => "egress",
        Direction::Ingress => "ingress",
    };
    format!(
        "{} {}:{} {}:{} {} {direction} {} {}",
        flow.node,
        flow.key.src_ip,
        flow.key.src_port,
        flow.key.dst_ip,
        flow.key.dst_port,
        protocol_name(flow.key.protocol),
        pod_label(flow.src_pod.as_ref()),
        pod_label(flow.dst_pod.as_ref()),
    )
    .to_lowercase()
    .contains(query)
}

/// Client-side substring filter over node, pods, IPs, ports, and protocol.
fn filter_flows(flows: &[FlowRecord], query: &str) -> Vec<FlowRecord> {
    let query = query.trim().to_lowercase();
    flows
        .iter()
        .filter(|flow| flow_matches(flow, &query))
        .cloned()
        .collect()
}

/// Flows table: time / node / pod / direction / src→dst / proto / bytes / packets.
#[component]
pub fn FlowsView() -> impl IntoView {
    let state = expect_context::<AppState>();
    let loading = RwSignal::new(true);
    let error = RwSignal::new(Option::<String>::None);
    let limit = RwSignal::new(200_usize);
    let query = RwSignal::new(String::new());
    let filtered = Memo::new(move |_| filter_flows(&state.flows.get(), &query.get()));

    // REST snapshot, reloaded whenever the token or limit changes
    // (WS prepends on top of this).
    Effect::new(move || {
        let Some(token) = state.token.get() else {
            return;
        };
        let limit = limit.get();
        loading.set(true);
        let flows_signal = state.flows;
        let session = state;
        leptos::task::spawn_local(async move {
            match fetch_flows(&token, limit).await {
                Ok(flows) => {
                    flows_signal.set(flows);
                    error.set(None);
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
        <section class="flows">
            <h2>"Flows"</h2>
            <div class="filters">
                <label>
                    "Limit"
                    <select
                        on:change=move |ev| {
                            limit.set(event_target_value(&ev).parse().unwrap_or(200));
                        }
                        prop:value=move || limit.get().to_string()
                    >
                        {FLOW_LIMITS
                            .into_iter()
                            .map(|n| {
                                view! { <option value=n.to_string()>{n.to_string()}</option> }
                            })
                            .collect::<Vec<_>>()}
                    </select>
                </label>
                <label>
                    "Search"
                    <input
                        type="search"
                        placeholder="Filter flows…"
                        spellcheck="false"
                        autocomplete="off"
                        on:input=move |ev| {
                            query.set(event_target_value(&ev));
                        }
                        prop:value=move || query.get()
                    />
                </label>
            </div>
            <Show when=move || error.get().is_some()>
                <p class="error" aria-live="polite">
                    {move || error.get().unwrap_or_default()}
                </p>
            </Show>
            <Show
                when=move || !loading.get() || !state.flows.get().is_empty()
                fallback=|| view! { <p class="muted">"Loading flows…"</p> }
            >
                <Show
                    when=move || !filtered.get().is_empty()
                    fallback=move || {
                        view! {
                            <p class="muted">
                                {if state.flows.get().is_empty() {
                                    "No flows yet."
                                } else {
                                    "No flows match this filter."
                                }}
                            </p>
                        }
                    }
                >
                    <FlowsTable flows=filtered />
                </Show>
            </Show>
        </section>
    }
}

/// Scrollable flows table; the wrapper scrolls horizontally on narrow
/// screens instead of squeezing the eight columns.
#[component]
fn FlowsTable(flows: Memo<Vec<FlowRecord>>) -> impl IntoView {
    view! {
        <div class="table-scroll">
            <table>
                <thead>
                    <tr>
                        <th>"Time"</th>
                        <th>"Node"</th>
                        <th>"Pod"</th>
                        <th>"Dir"</th>
                        <th>"Source → Dest"</th>
                        <th>"Proto"</th>
                        <th class="num">"Bytes"</th>
                        <th class="num">"Packets"</th>
                    </tr>
                </thead>
                <tbody>
                    <For
                        each=move || flows.get()
                        key=|flow| flow.row_key()
                        let(flow)
                    >
                        <tr>
                            <td>{format_time_ms(flow.last_seen_unix_ms)}</td>
                            <td>{flow.node.clone()}</td>
                            <td>
                                {match flow.direction {
                                    Direction::Egress => {
                                        pod_label(flow.src_pod.as_ref())
                                    }
                                    Direction::Ingress => {
                                        pod_label(flow.dst_pod.as_ref())
                                    }
                                }}
                            </td>
                            <td>
                                {match flow.direction {
                                    Direction::Egress => "egress",
                                    Direction::Ingress => "ingress",
                                }}
                            </td>
                            <td class="mono">
                                {format!(
                                    "{}:{} → {}:{}",
                                    flow.key.src_ip,
                                    flow.key.src_port,
                                    flow.key.dst_ip,
                                    flow.key.dst_port,
                                )}
                            </td>
                            <td class="mono">{protocol_name(flow.key.protocol)}</td>
                            <td class="num">{flow.bytes.to_string()}</td>
                            <td class="num">{flow.packets.to_string()}</td>
                        </tr>
                    </For>
                </tbody>
            </table>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::FlowKey;

    fn flow(node: &str, src_ip: &str, protocol: u8, pod: Option<&str>) -> FlowRecord {
        FlowRecord {
            key: FlowKey {
                src_ip: src_ip.to_owned(),
                src_port: 54321,
                dst_ip: "10.0.0.2".to_owned(),
                dst_port: 443,
                protocol,
            },
            direction: Direction::Egress,
            bytes: 100,
            packets: 1,
            start_unix_ms: 0,
            last_seen_unix_ms: 0,
            node: node.to_owned(),
            src_pod: pod.map(|name| crate::dto::PodRef {
                namespace: "default".to_owned(),
                name: name.to_owned(),
            }),
            dst_pod: None,
        }
    }

    #[test]
    fn search_matches_node_ip_pod_and_protocol() {
        let flows = vec![
            flow("node-1", "10.0.0.9", 6, Some("web-0")),
            flow("node-2", "10.0.0.8", 17, Some("db-0")),
        ];
        assert_eq!(filter_flows(&flows, "").len(), 2);
        assert_eq!(filter_flows(&flows, "  ").len(), 2);
        assert_eq!(filter_flows(&flows, "node-2").len(), 1);
        assert_eq!(filter_flows(&flows, "10.0.0.9").len(), 1);
        assert_eq!(filter_flows(&flows, "WEB-0").len(), 1);
        assert_eq!(filter_flows(&flows, "udp").len(), 1);
        assert_eq!(filter_flows(&flows, "54321").len(), 2);
        assert_eq!(filter_flows(&flows, "zzz-no-such-flow").len(), 0);
    }
}
