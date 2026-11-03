//! Health view: API uptime, analyzer queue pressure, and per-agent
//! heartbeats with eBPF map-pressure counters.

use leptos::prelude::*;

use crate::api::fetch_health_overview;
use crate::dto::{AgentHealth, HealthOverview};
use crate::state::{AppState, format_time_ms};

/// Health page: system stats plus the agent heartbeat table.
#[component]
pub fn HealthView() -> impl IntoView {
    let state = expect_context::<AppState>();
    let overview = RwSignal::new(Option::<HealthOverview>::None);
    let loading = RwSignal::new(false);
    let error = RwSignal::new(Option::<String>::None);

    // Load once on first visit.
    Effect::new(move || {
        if state.token.get().is_some() && overview.get_untracked().is_none() {
            refresh(state, overview, loading, error);
        }
    });

    view! {
        <section class="health">
            <h2>"Health"</h2>
            <p class="muted">
                "API status and per-agent heartbeats. Agents ship every few seconds; \
                 a node with no recent batch reads stale."
            </p>
            <div class="filters">
                <button
                    on:click=move |_| {
                        refresh(state, overview, loading, error);
                    }
                    disabled=move || loading.get()
                >
                    {move || if loading.get() { "Refreshing…" } else { "Refresh" }}
                </button>
            </div>
            <Show when=move || error.get().is_some()>
                <p class="error" aria-live="polite">
                    {move || error.get().unwrap_or_default()}
                </p>
            </Show>
            <Show
                when=move || overview.get().is_some()
                fallback=move || {
                    view! {
                        <Show when=move || loading.get()>
                            <p class="muted">"Loading health…"</p>
                        </Show>
                    }
                }
            >
                {move || {
                    overview.get().map(|data| {
                        view! {
                            <HealthStats data=data.clone() />
                            <AgentsTable agents=data.agents.clone() />
                        }
                    })
                }}
            </Show>
        </section>
    }
}

/// Fetch the overview and store it, logging out on 401.
fn refresh(
    state: AppState,
    overview: RwSignal<Option<HealthOverview>>,
    loading: RwSignal<bool>,
    error: RwSignal<Option<String>>,
) {
    let Some(token) = state.token.get() else {
        return;
    };
    if loading.get_untracked() {
        return;
    }
    loading.set(true);
    error.set(None);
    let session = state;
    leptos::task::spawn_local(async move {
        match fetch_health_overview(&token).await {
            Ok(data) => {
                overview.set(Some(data));
            }
            Err(err) => {
                session.logout_if_unauthorized(&err);
                error.set(Some(err.to_string()));
            }
        }
        loading.set(false);
    });
}

/// Top stat row: uptime, storage, queue, subscribers, live agents.
#[component]
fn HealthStats(data: HealthOverview) -> impl IntoView {
    let live = data.agents.iter().filter(|agent| !agent.stale).count();
    view! {
        <div class="stats">
            <div class="stat">
                <span class="stat-value">{format_uptime(data.uptime_secs)}</span>
                <span class="stat-label">"API uptime"</span>
            </div>
            <div class="stat">
                <span class="stat-value">{data.storage.clone()}</span>
                <span class="stat-label">"Storage"</span>
            </div>
            <div class="stat">
                <span class="stat-value">
                    {format!("{}/{}", data.analyzer_queue.depth, data.analyzer_queue.capacity)}
                </span>
                <span class="stat-label">"Analyzer queue"</span>
            </div>
            <div class="stat">
                <span class="stat-value">{data.ws_subscribers.to_string()}</span>
                <span class="stat-label">"WS subscribers"</span>
            </div>
            <div class="stat">
                <span class="stat-value">
                    {format!("{}/{}", live, data.agents.len())}
                </span>
                <span class="stat-label">"Agents live"</span>
            </div>
        </div>
    }
}

/// Per-agent heartbeat table with eBPF pressure counters.
#[component]
fn AgentsTable(agents: Vec<AgentHealth>) -> impl IntoView {
    // Eager: the rows are a one-shot snapshot, not a live signal.
    let empty = agents.is_empty();
    view! {
        <div class="table-scroll">
            <table>
                <thead>
                    <tr>
                        <th>"Node"</th>
                        <th>"Status"</th>
                        <th>"Last seen"</th>
                        <th class="num">"Batches"</th>
                        <th class="num">"Flows"</th>
                        <th class="num">"eBPF updated"</th>
                        <th class="num">"Skipped"</th>
                        <th class="num">"Map full"</th>
                    </tr>
                </thead>
                <tbody>
                    <For
                        each=move || agents.clone()
                        key=|agent| agent.node.clone()
                        let(agent)
                    >
                        <tr>
                            <td class="mono">{agent.node.clone()}</td>
                            <td>
                                {if agent.stale {
                                    view! { <span class="sev sev-warning">"stale"</span> }.into_any()
                                } else {
                                    view! { <span class="sev sev-info">"live"</span> }.into_any()
                                }}
                            </td>
                            <td>
                                {format!(
                                    "{} ({}s ago)",
                                    format_time_ms(agent.last_seen_ms),
                                    agent.age_secs,
                                )}
                            </td>
                            <td class="num">{agent.batches_total.to_string()}</td>
                            <td class="num">{agent.flows_total.to_string()}</td>
                            <td class="num">{agent.updated.to_string()}</td>
                            <td class="num">{agent.skipped.to_string()}</td>
                            <td class="num">
                                {if agent.map_full > 0 {
                                    view! {
                                        <span class="sev sev-warning">
                                            {agent.map_full.to_string()}
                                        </span>
                                    }
                                        .into_any()
                                } else {
                                    view! { {agent.map_full.to_string()} }.into_any()
                                }}
                            </td>
                        </tr>
                    </For>
                </tbody>
            </table>
        </div>
        <Show when=move || empty>
            <p class="muted">"No agents have reported yet."</p>
        </Show>
    }
}

/// Compact uptime: `45s`, `3m 12s`, `2h 5m`, `6d 3h`.
pub(crate) fn format_uptime(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3_600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else if secs < 86_400 {
        format!("{}h {}m", secs / 3_600, (secs % 3_600) / 60)
    } else {
        format!("{}d {}h", secs / 86_400, (secs % 86_400) / 3_600)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overview_shape_parses() {
        let data: HealthOverview = serde_json::from_str(
            r#"{"uptime_secs":90,"storage":"postgres",
                "analyzer_queue":{"depth":1,"capacity":64},
                "ws_subscribers":2,
                "agents":[{"node":"kind-worker","last_seen_ms":1000,
                "age_secs":5,"stale":false,"batches_total":10,
                "flows_total":40,"updated":100,"skipped":3,
                "map_full":0}]}"#,
        )
        .expect("must parse");
        assert_eq!(data.storage, "postgres");
        assert_eq!(data.analyzer_queue.depth, 1);
        assert_eq!(data.agents.len(), 1);
        assert!(!data.agents[0].stale);
    }

    #[test]
    fn uptime_formats_compactly() {
        assert_eq!(format_uptime(45), "45s");
        assert_eq!(format_uptime(192), "3m 12s");
        assert_eq!(format_uptime(7_500), "2h 5m");
        assert_eq!(format_uptime(529_200), "6d 3h");
    }
}
