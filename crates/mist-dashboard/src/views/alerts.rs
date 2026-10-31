//! Alerts view: filterable list + detail panel with a resolve action.

use leptos::prelude::*;

use crate::api::{fetch_alert, fetch_alerts, resolve_alert};
use crate::dto::{AlertState, AlertView, Severity};
use crate::state::{AppState, format_time_ms};

/// Severity badge text + CSS class.
pub(crate) fn severity_badge(severity: Severity) -> (&'static str, &'static str) {
    match severity {
        Severity::Info => ("info", "sev-info"),
        Severity::Warning => ("warning", "sev-warning"),
        Severity::Critical => ("critical", "sev-critical"),
    }
}

fn state_label(state: AlertState) -> &'static str {
    match state {
        AlertState::Firing => "firing",
        AlertState::Resolved => "resolved",
    }
}

/// Whether an alert's display fields contain the (already lowercased) query.
fn alert_matches(alert: &AlertView, query: &str) -> bool {
    if query.is_empty() {
        return true;
    }
    let labels = alert
        .labels
        .iter()
        .map(|(key, value)| format!("{key} {value}"))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "{} {} {} {} {} {labels}",
        alert.id,
        alert.title,
        alert.detail,
        severity_badge(alert.severity).0,
        state_label(alert.state),
    )
    .to_lowercase()
    .contains(query)
}

/// Client-side substring filter over id, title, detail, labels, and badges.
fn filter_alerts(alerts: &[AlertView], query: &str) -> Vec<AlertView> {
    let query = query.trim().to_lowercase();
    alerts
        .iter()
        .filter(|alert| alert_matches(alert, &query))
        .cloned()
        .collect()
}

/// Alerts list with severity/state filters and a detail panel.
#[component]
pub fn AlertsView() -> impl IntoView {
    let state = expect_context::<AppState>();
    let severity_filter = RwSignal::new("all".to_owned());
    let state_filter = RwSignal::new("all".to_owned());
    let selected = RwSignal::new(Option::<String>::None);
    let detail = RwSignal::new(Option::<AlertView>::None);
    let detail_loading = RwSignal::new(false);
    let action_error = RwSignal::new(Option::<String>::None);
    let list_error = RwSignal::new(Option::<String>::None);
    let list_loaded = RwSignal::new(false);
    let resolving = RwSignal::new(false);
    let query = RwSignal::new(String::new());
    let filtered = Memo::new(move |_| filter_alerts(&state.alerts.get(), &query.get()));

    // Refetch the list whenever the token or a filter changes.
    Effect::new(move || {
        let token = state.token.get();
        let severity = severity_filter.get();
        let alert_state = state_filter.get();
        let Some(token) = token else {
            return;
        };
        let alerts_signal = state.alerts;
        let session = state;
        leptos::task::spawn_local(async move {
            let sev = (severity != "all").then_some(severity.as_str());
            let st = (alert_state != "all").then_some(alert_state.as_str());
            match fetch_alerts(&token, st, sev, 200).await {
                Ok(alerts) => {
                    alerts_signal.set(alerts);
                    list_error.set(None);
                }
                Err(err) => {
                    session.logout_if_unauthorized(&err);
                    list_error.set(Some(err.to_string()));
                }
            }
            list_loaded.set(true);
        });
    });

    // Load the selected alert's detail.
    Effect::new(move || {
        let token = state.token.get();
        let id = selected.get();
        let (Some(token), Some(id)) = (token, id) else {
            detail.set(None);
            return;
        };
        detail_loading.set(true);
        detail.set(None);
        let session = state;
        leptos::task::spawn_local(async move {
            match fetch_alert(&token, &id).await {
                Ok(alert) => {
                    detail.set(Some(alert));
                    action_error.set(None);
                }
                Err(err) => {
                    session.logout_if_unauthorized(&err);
                    action_error.set(Some(err.to_string()));
                }
            }
            detail_loading.set(false);
        });
    });

    view! {
        <section class="alerts">
            <h2>"Alerts"</h2>
            <AlertFilters
                severity_filter=severity_filter
                state_filter=state_filter
                query=query
            />
            <Show when=move || list_error.get().is_some()>
                <p class="error" aria-live="polite">
                    {move || list_error.get().unwrap_or_default()}
                </p>
            </Show>
            <div class="alerts-layout">
                <AlertListColumn
                    filtered=filtered
                    alerts=state.alerts
                    list_loaded=list_loaded
                    selected=selected
                />
                <div class="alert-detail">
                    <AlertDetail
                        detail=detail
                        loading=detail_loading
                        error=action_error
                        resolving=resolving
                    />
                </div>
            </div>
        </section>
    }
}

/// Alert list column: filtered rows, or a hint distinguishing an empty
/// result (filters) from a search miss.
#[component]
fn AlertListColumn(
    filtered: Memo<Vec<AlertView>>,
    alerts: RwSignal<Vec<AlertView>>,
    list_loaded: RwSignal<bool>,
    selected: RwSignal<Option<String>>,
) -> impl IntoView {
    view! {
        <Show
            when=move || !filtered.get().is_empty() || !list_loaded.get()
            fallback=move || {
                view! {
                    <p class="muted">
                        {if alerts.get().is_empty() {
                            "No alerts match these filters."
                        } else {
                            "No alerts match this search."
                        }}
                    </p>
                }
            }
        >
            <ul class="alert-list">
                <For
                    each=move || filtered.get()
                    key=|alert| alert.id.clone()
                    let(alert)
                >
                    <AlertListItem alert=alert selected=selected />
                </For>
            </ul>
        </Show>
    }
}

/// Severity/state filter selects shared by the list effect.
#[component]
fn AlertFilters(
    severity_filter: RwSignal<String>,
    state_filter: RwSignal<String>,
    query: RwSignal<String>,
) -> impl IntoView {
    let severities = ["all", "info", "warning", "critical"];
    let states = ["all", "firing", "resolved"];
    view! {
        <div class="filters">
            <label>
                "Severity"
                <select
                    on:change=move |ev| {
                        severity_filter.set(event_target_value(&ev));
                    }
                    prop:value=move || severity_filter.get()
                >
                    {severities
                        .into_iter()
                        .map(|s| {
                            view! { <option value=s>{s}</option> }
                        })
                        .collect::<Vec<_>>()}
                </select>
            </label>
            <label>
                "State"
                <select
                    on:change=move |ev| {
                        state_filter.set(event_target_value(&ev));
                    }
                    prop:value=move || state_filter.get()
                >
                    {states
                        .into_iter()
                        .map(|s| {
                            view! { <option value=s>{s}</option> }
                        })
                        .collect::<Vec<_>>()}
                </select>
            </label>
            <label>
                "Search"
                <input
                    type="search"
                    placeholder="Filter alerts…"
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

/// One row in the alert list; click selects it for the detail panel.
#[component]
fn AlertListItem(alert: AlertView, selected: RwSignal<Option<String>>) -> impl IntoView {
    let id = alert.id.clone();
    let (sev_label, sev_class) = severity_badge(alert.severity);
    let title = alert.title.clone();
    let alert_state = alert.state;
    let is_selected = move || selected.get().as_deref() == Some(id.as_str());
    view! {
        <li>
            <button
                class=move || {
                    if is_selected() { "alert-item selected" } else { "alert-item" }
                }
                on:click=move |_| {
                    selected.set(Some(alert.id.clone()));
                }
            >
                <span class=format!("sev {sev_class}")>{sev_label}</span>
                <span class="alert-title">{title}</span>
                <span class="alert-state">{state_label(alert_state)}</span>
            </button>
        </li>
    }
}

/// Detail panel for the selected alert, with a resolve button while firing.
#[component]
fn AlertDetail(
    detail: RwSignal<Option<AlertView>>,
    loading: RwSignal<bool>,
    error: RwSignal<Option<String>>,
    resolving: RwSignal<bool>,
) -> impl IntoView {
    let state = expect_context::<AppState>();
    view! {
        <Show
            when=move || loading.get()
            fallback=move || {
                view! {
                    <Show
                        when=move || detail.get().is_some()
                        fallback=|| view! { <p class="muted">"Select an alert."</p> }
                    >
                        {move || {
                            detail.get().map(|alert| {
                                view! {
                                    <AlertBody
                                        alert=alert
                                        detail=detail
                                        error=error
                                        resolving=resolving
                                        state=state
                                    />
                                }
                            })
                        }}
                    </Show>
                }
            }
        >
            <p class="muted">"Loading alert…"</p>
        </Show>
    }
}

/// The loaded alert article (title, explanation, labels, resolve button).
#[component]
fn AlertBody(
    alert: AlertView,
    detail: RwSignal<Option<AlertView>>,
    error: RwSignal<Option<String>>,
    resolving: RwSignal<bool>,
    state: AppState,
) -> impl IntoView {
    let (sev_label, sev_class) = severity_badge(alert.severity);
    let is_firing = alert.state == AlertState::Firing;
    let has_explanation = alert
        .explanation
        .as_ref()
        .is_some_and(|text| !text.is_empty());
    let label_rows = alert
        .labels
        .iter()
        .map(|(key, value)| {
            view! {
                <tr>
                    <td class="mono">{key.clone()}</td>
                    <td class="mono">{value.clone()}</td>
                </tr>
            }
        })
        .collect::<Vec<_>>();
    view! {
        <article>
            <h3>{alert.title.clone()}</h3>
            <p>
                <span class=format!("sev {sev_class}")>{sev_label}</span>
                " "
                {state_label(alert.state)}
                " · "
                {format!("{} occurrences", alert.occurrences)}
            </p>
            <p>{alert.detail.clone()}</p>
            <p class="muted">
                {format!(
                    "first {} · last {}",
                    format_time_ms(alert.first_seen_unix_ms),
                    format_time_ms(alert.last_seen_unix_ms),
                )}
            </p>
            <Show when=move || has_explanation>
                <h4>"Why this fired"</h4>
                <p class="explanation">
                    {alert.explanation.clone().unwrap_or_default()}
                </p>
            </Show>
            <h4>"Labels"</h4>
            <table class="labels">
                <tbody>{label_rows}</tbody>
            </table>
            <Show when=move || error.get().is_some()>
                <p class="error" aria-live="polite">
                    {move || error.get().unwrap_or_default()}
                </p>
            </Show>
            <Show when=move || is_firing>
                <button
                    on:click=move |_| {
                        let (Some(token), Some(current)) = (
                            state.token.get_untracked(),
                            detail.get_untracked(),
                        ) else {
                            return;
                        };
                        if resolving.get_untracked() {
                            return;
                        }
                        resolving.set(true);
                        error.set(None);
                        let alerts = state.alerts;
                        let session = state;
                        leptos::task::spawn_local(async move {
                            match resolve_alert(&token, &current.id).await {
                                Ok(updated) => {
                                    detail.set(Some(updated.clone()));
                                    alerts.update(|list| {
                                        if let Some(existing) = list
                                            .iter_mut()
                                            .find(|item| item.id == updated.id)
                                        {
                                            *existing = updated;
                                        }
                                    });
                                }
                                Err(err) => {
                                    session.logout_if_unauthorized(&err);
                                    error.set(Some(err.to_string()));
                                }
                            }
                            resolving.set(false);
                        });
                    }
                    disabled=move || resolving.get()
                >
                    {move || {
                        if resolving.get() {
                            "Resolving…"
                        } else {
                            "Resolve"
                        }
                    }}
                </button>
            </Show>
        </article>
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn alert(id: &str, title: &str, severity: Severity, state: AlertState) -> AlertView {
        AlertView {
            id: id.to_owned(),
            severity,
            title: title.to_owned(),
            detail: "egress exceeds threshold".to_owned(),
            first_seen_unix_ms: 0,
            last_seen_unix_ms: 0,
            labels: BTreeMap::from([("node".to_owned(), "node-1".to_owned())]),
            explanation: None,
            state,
            occurrences: 1,
        }
    }

    #[test]
    fn search_matches_title_id_severity_and_labels() {
        let alerts = vec![
            alert(
                "default/web-0/high-egress",
                "High egress rate",
                Severity::Warning,
                AlertState::Firing,
            ),
            alert(
                "default/db-0/port-scan",
                "Port scan detected",
                Severity::Critical,
                AlertState::Resolved,
            ),
        ];
        assert_eq!(filter_alerts(&alerts, "").len(), 2);
        assert_eq!(filter_alerts(&alerts, "PORT SCAN").len(), 1);
        assert_eq!(filter_alerts(&alerts, "web-0/high-egress").len(), 1);
        assert_eq!(filter_alerts(&alerts, "critical").len(), 1);
        assert_eq!(filter_alerts(&alerts, "resolved").len(), 1);
        assert_eq!(filter_alerts(&alerts, "node-1").len(), 2);
        assert_eq!(filter_alerts(&alerts, "zzz-no-such-alert").len(), 0);
    }
}
