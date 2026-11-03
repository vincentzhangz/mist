//! Flows view: REST snapshot + live WS prepend, capped rows.

use leptos::prelude::*;

use super::paging::{MAX_CHAIN, append_new_rows, merge_rows};
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
    let loading_more = RwSignal::new(false);
    let error = RwSignal::new(Option::<String>::None);
    let limit = RwSignal::new(200_usize);
    let query = RwSignal::new(String::new());
    // View-local history: page one plus appended older pages. Kept apart
    // from the shared live signal so WS prepends (capped at 500) never
    // truncate loaded history.
    let history = RwSignal::new(Vec::<FlowRecord>::new());
    let cursor = RwSignal::new(Option::<u64>::None);
    let exhausted = RwSignal::new(false);
    let paged = RwSignal::new(false);
    let merged = Memo::new(move |_| merge_rows(&state.flows.get(), &history.get()));
    let filtered = Memo::new(move |_| filter_flows(&merged.get(), &query.get()));

    // Page one, reloaded whenever the token or limit changes.
    Effect::new(move || {
        let Some(token) = state.token.get() else {
            return;
        };
        let limit = limit.get();
        loading.set(true);
        let history_signal = history;
        let cursor_signal = cursor;
        let exhausted_signal = exhausted;
        let paged_signal = paged;
        let session = state;
        leptos::task::spawn_local(async move {
            match fetch_flows(&token, limit, None).await {
                Ok(page) => {
                    history_signal.set(page.flows);
                    cursor_signal.set(page.next_cursor);
                    exhausted_signal.set(page.next_cursor.is_none());
                    paged_signal.set(false);
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
            <FlowsFilters limit=limit query=query />
            <Show when=move || error.get().is_some()>
                <p class="error" aria-live="polite">
                    {move || error.get().unwrap_or_default()}
                </p>
            </Show>
            <Show
                when=move || !loading.get() || !merged.get().is_empty()
                fallback=|| view! { <p class="muted">"Loading flows…"</p> }
            >
                <Show
                    when=move || !filtered.get().is_empty()
                    fallback=move || {
                        view! {
                            <p class="muted">
                                {if merged.get().is_empty() {
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
                <Show when=move || !history.get().is_empty() && !exhausted.get()>
                    <button
                        on:click=move |_| {
                            load_more(state, Paging {
                                history,
                                cursor,
                                exhausted,
                                paged,
                                loading_more,
                                error,
                                limit,
                                merged,
                            });
                        }
                        disabled=move || loading_more.get()
                    >
                        {move || if loading_more.get() { "Loading…" } else { "Load more" }}
                    </button>
                </Show>
                <Show when=move || paged.get() && exhausted.get()>
                    <p class="muted">"No more flows."</p>
                </Show>
            </Show>
        </section>
    }
}

/// Limit select + search input for the flows view.
#[component]
fn FlowsFilters(limit: RwSignal<usize>, query: RwSignal<String>) -> impl IntoView {
    view! {
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
    }
}

/// View-local paging state for the flows history.
#[derive(Clone, Copy)]
struct Paging {
    history: RwSignal<Vec<FlowRecord>>,
    cursor: RwSignal<Option<u64>>,
    exhausted: RwSignal<bool>,
    paged: RwSignal<bool>,
    loading_more: RwSignal<bool>,
    error: RwSignal<Option<String>>,
    limit: RwSignal<usize>,
    merged: Memo<Vec<FlowRecord>>,
}

/// Fetch older pages until the merged table visibly grows or history ends.
/// Chaining matters because fetched pages can hide entirely inside the
/// live window; without it a click would sometimes do nothing visible.
/// Stops at an absent cursor, or when the cursor stops advancing (only
/// boundary repeats remain: the exact-multiple tail).
fn load_more(state: AppState, paging: Paging) {
    let Some(token) = state.token.get() else {
        return;
    };
    let Some(first) = paging.cursor.get_untracked() else {
        return;
    };
    if paging.loading_more.get_untracked() || paging.exhausted.get_untracked() {
        return;
    }
    paging.loading_more.set(true);
    let page_size = paging.limit.get_untracked();
    let session = state;
    leptos::task::spawn_local(async move {
        let start_len = paging.merged.get_untracked().len();
        let mut before = first;
        for _ in 0..MAX_CHAIN {
            let page = match fetch_flows(&token, page_size, Some(before)).await {
                Ok(page) => page,
                Err(err) => {
                    session.logout_if_unauthorized(&err);
                    paging.error.set(Some(err.to_string()));
                    break;
                }
            };
            // Plain `update`: the `_untracked` twin would not notify
            // the merged memo, freezing the table.
            paging.history.update(|rows| {
                append_new_rows(rows, &page.flows);
            });
            paging.paged.set(true);
            paging.error.set(None);
            match page.next_cursor {
                Some(next) if next != before => {
                    paging.cursor.set(Some(next));
                    before = next;
                    if paging.merged.get_untracked().len() > start_len {
                        break;
                    }
                }
                Some(_) => {
                    // Cursor stuck: every further page repeats this one.
                    paging.exhausted.set(true);
                    break;
                }
                None => {
                    paging.cursor.set(None);
                    paging.exhausted.set(true);
                    break;
                }
            }
        }
        paging.loading_more.set(false);
    });
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

    #[test]
    fn merge_rows_dedupes_flows_by_key() {
        let a = flow("node-1", "10.0.0.9", 6, Some("web-0"));
        let mut newer = a.clone();
        newer.last_seen_unix_ms = 2500;
        // Exact repeat collapses; same tuple at another time is kept.
        let live = [a.clone()];
        let history = [a, newer];
        let merged = merge_rows(&live, &history);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].last_seen_unix_ms, 2500);
        assert_eq!(merged[1].last_seen_unix_ms, 0);
    }
}
