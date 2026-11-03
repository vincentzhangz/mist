//! Alerts view: filterable list + detail panel with ack, silence, and
//! resolve actions.

use leptos::prelude::*;

use super::paging::{MAX_CHAIN, append_new_rows, merge_rows};
use crate::api::{delete_silence, fetch_alert, fetch_alerts, fetch_silences};
use crate::dto::{AlertState, AlertView, Severity, Silence};
use crate::state::{AppState, format_time_ms};

mod detail;

use detail::AlertDetail;

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
        AlertState::Acknowledged => "acknowledged",
        AlertState::Resolved => "resolved",
    }
}

/// One-line summary of a silence rule for the muted list.
fn silence_summary(rule: &Silence) -> String {
    let mut parts = Vec::new();
    if let Some(severity) = &rule.severity {
        parts.push(severity.clone());
    }
    if let Some(query) = &rule.title_contains {
        parts.push(format!("title~\"{query}\""));
    }
    if let Some(id) = &rule.alert_id {
        parts.push(format!("alert={id}"));
    }
    if let Some(key) = &rule.label_key {
        match &rule.label_value {
            Some(value) => parts.push(format!("{key}={value}")),
            None => parts.push(key.clone()),
        }
    }
    if parts.is_empty() {
        parts.push("all alerts".to_owned());
    }
    parts.push(format!("until {}", format_time_ms(rule.ends_at_ms)));
    parts.join(" · ")
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
    let query = RwSignal::new(String::new());
    // View-local history: page one plus appended older pages. Kept apart
    // from the shared live signal so WS upserts and other views' fetches
    // never truncate loaded history (mirrors the flows view).
    let history = RwSignal::new(Vec::<AlertView>::new());
    let cursor = RwSignal::new(Option::<u64>::None);
    let exhausted = RwSignal::new(false);
    let paged = RwSignal::new(false);
    let loading_more = RwSignal::new(false);
    let merged = Memo::new(move |_| merge_rows(&state.alerts.get(), &history.get()));
    let filtered = Memo::new(move |_| filter_alerts(&merged.get(), &query.get()));
    let silences = RwSignal::new(Vec::<Silence>::new());
    let paging = AlertPaging {
        history,
        cursor,
        exhausted,
        paged,
        loading_more,
        list_error,
        list_loaded,
        merged,
    };

    load_alerts_data(state, severity_filter, state_filter, silences, paging);

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
            <SilenceList silences=silences session=state error=list_error />
            <div class="alerts-layout">
                <div>
                    <AlertListColumn
                        filtered=filtered
                        alerts=merged
                        list_loaded=list_loaded
                        selected=selected
                    />
                    <Show when=move || !history.get().is_empty() && !exhausted.get()>
                        <button
                            on:click=move |_| {
                                load_more_alerts(state, severity_filter, state_filter, paging);
                            }
                            disabled=move || loading_more.get()
                        >
                            {move || if loading_more.get() { "Loading…" } else { "Load more" }}
                        </button>
                    </Show>
                    <Show when=move || paged.get() && exhausted.get()>
                        <p class="muted">"No more alerts."</p>
                    </Show>
                </div>
                <div class="alert-detail">
                    <AlertDetail
                        detail=detail
                        loading=detail_loading
                        error=action_error
                        silences=silences
                    />
                </div>
            </div>
        </section>
    }
}

/// Alerts fetched per page (initial and Load-more).
const ALERT_PAGE_SIZE: usize = 200;

/// View-local paging state for the alerts history.
#[derive(Clone, Copy)]
struct AlertPaging {
    history: RwSignal<Vec<AlertView>>,
    cursor: RwSignal<Option<u64>>,
    exhausted: RwSignal<bool>,
    paged: RwSignal<bool>,
    loading_more: RwSignal<bool>,
    list_error: RwSignal<Option<String>>,
    list_loaded: RwSignal<bool>,
    merged: Memo<Vec<AlertView>>,
}

/// Fetch effects for the alert list (page one, refetched on token/filter
/// change) and the silence rules (once per session).
fn load_alerts_data(
    state: AppState,
    severity_filter: RwSignal<String>,
    state_filter: RwSignal<String>,
    silences: RwSignal<Vec<Silence>>,
    paging: AlertPaging,
) {
    Effect::new(move || {
        let token = state.token.get();
        let severity = severity_filter.get();
        let alert_state = state_filter.get();
        let Some(token) = token else {
            return;
        };
        let session = state;
        leptos::task::spawn_local(async move {
            let sev = (severity != "all").then_some(severity.as_str());
            let st = (alert_state != "all").then_some(alert_state.as_str());
            match fetch_alerts(&token, st, sev, ALERT_PAGE_SIZE, None).await {
                Ok(page) => {
                    paging.history.set(page.alerts);
                    paging.cursor.set(page.next_cursor);
                    paging.exhausted.set(page.next_cursor.is_none());
                    paging.paged.set(false);
                    paging.list_error.set(None);
                }
                Err(err) => {
                    session.logout_if_unauthorized(&err);
                    paging.list_error.set(Some(err.to_string()));
                }
            }
            paging.list_loaded.set(true);
        });
    });

    Effect::new(move || {
        let Some(token) = state.token.get() else {
            return;
        };
        let session = state;
        leptos::task::spawn_local(async move {
            match fetch_silences(&token).await {
                Ok(rules) => {
                    silences.set(rules);
                }
                Err(err) => {
                    session.logout_if_unauthorized(&err);
                    paging.list_error.set(Some(err.to_string()));
                }
            }
        });
    });
}

/// Fetch older alert pages until the merged list visibly grows or history
/// ends. Follow-ups re-send the active filters, and chaining stops when
/// the cursor stalls (only boundary repeats remain: the exact-multiple
/// tail). Mirrors the flows `load_more`.
fn load_more_alerts(
    state: AppState,
    severity_filter: RwSignal<String>,
    state_filter: RwSignal<String>,
    paging: AlertPaging,
) {
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
    let severity = severity_filter.get_untracked();
    let alert_state = state_filter.get_untracked();
    let session = state;
    leptos::task::spawn_local(async move {
        let start_len = paging.merged.get_untracked().len();
        let mut before = first;
        let sev = (severity != "all").then_some(severity.as_str());
        let st = (alert_state != "all").then_some(alert_state.as_str());
        for _ in 0..MAX_CHAIN {
            let page = match fetch_alerts(&token, st, sev, ALERT_PAGE_SIZE, Some(before)).await {
                Ok(page) => page,
                Err(err) => {
                    session.logout_if_unauthorized(&err);
                    paging.list_error.set(Some(err.to_string()));
                    break;
                }
            };
            // Plain `update`: the `_untracked` twin would not notify
            // the merged memo, freezing the list.
            paging.history.update(|rows| {
                append_new_rows(rows, &page.alerts);
            });
            paging.paged.set(true);
            paging.list_error.set(None);
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

/// Alert list column: filtered rows, or a hint distinguishing an empty
/// result (filters) from a search miss.
#[component]
fn AlertListColumn(
    filtered: Memo<Vec<AlertView>>,
    alerts: Memo<Vec<AlertView>>,
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
    let states = ["all", "firing", "acknowledged", "resolved"];
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
    let silenced = alert.silenced;
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
                <Show when=move || silenced>
                    <span class="chip">"muted"</span>
                </Show>
                <span class="alert-state">{state_label(alert_state)}</span>
            </button>
        </li>
    }
}

/// Active silence rules with delete buttons; hidden when empty.
#[component]
fn SilenceList(
    silences: RwSignal<Vec<Silence>>,
    session: AppState,
    error: RwSignal<Option<String>>,
) -> impl IntoView {
    let deleting = RwSignal::new(Option::<i64>::None);
    view! {
        <Show when=move || !silences.get().is_empty()>
            <div class="silences">
                <h3>"Muted"</h3>
                <ul class="silence-list">
                    <For
                        each=move || silences.get()
                        key=|rule| rule.id
                        let(rule)
                    >
                        <li>
                            <span class="silence-summary">{silence_summary(&rule)}</span>
                            <span class="muted">
                                {format!("by {}", rule.created_by.clone())}
                            </span>
                            <button
                                class="btn-ghost"
                                on:click={
                                    let id = rule.id;
                                    move |_| {
                                        let Some(token) = session.token.get_untracked() else {
                                            return;
                                        };
                                        if deleting.get_untracked().is_some() {
                                            return;
                                        }
                                        deleting.set(Some(id));
                                        error.set(None);
                                        leptos::task::spawn_local(async move {
                                            match delete_silence(&token, id).await {
                                                Ok(()) => {
                                                    silences.update(|rules| {
                                                        rules.retain(|kept| kept.id != id);
                                                    });
                                                }
                                                Err(err) => {
                                                    session.logout_if_unauthorized(&err);
                                                    error.set(Some(err.to_string()));
                                                }
                                            }
                                            deleting.set(None);
                                        });
                                    }
                                }
                                disabled=move || deleting.get().is_some()
                            >
                                "Unmute"
                            </button>
                        </li>
                    </For>
                </ul>
            </div>
        </Show>
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
            acked_by: None,
            ack_note: None,
            silenced: false,
        }
    }

    fn silence() -> Silence {
        Silence {
            id: 7,
            severity: Some("critical".to_owned()),
            title_contains: Some("scan".to_owned()),
            alert_id: None,
            label_key: Some("node".to_owned()),
            label_value: Some("node-1".to_owned()),
            starts_at_ms: 0,
            ends_at_ms: 3_600_000,
            created_by: "oncall@example.com".to_owned(),
            comment: String::new(),
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

    #[test]
    fn search_matches_acknowledged_state() {
        let alerts = vec![alert("a", "t", Severity::Info, AlertState::Acknowledged)];
        assert_eq!(filter_alerts(&alerts, "acknowledged").len(), 1);
    }

    #[test]
    fn merge_rows_dedupes_alerts_by_id() {
        let mut live = alert("a", "live", Severity::Critical, AlertState::Acknowledged);
        live.last_seen_unix_ms = 3000;
        let mut stale = alert("a", "stale", Severity::Critical, AlertState::Firing);
        stale.last_seen_unix_ms = 3000;
        // Same id: the stale copy collapses and the live one wins.
        let merged = merge_rows(&[live], &[stale]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].title, "live");
        assert_eq!(merged[0].state, AlertState::Acknowledged);
    }

    #[test]
    fn silence_summary_lists_matchers_and_expiry() {
        assert_eq!(
            silence_summary(&silence()),
            "critical · title~\"scan\" · node=node-1 · until 01:00:00"
        );
        let bare = Silence {
            severity: None,
            title_contains: None,
            alert_id: None,
            label_key: None,
            label_value: None,
            ..silence()
        };
        assert!(silence_summary(&bare).starts_with("all alerts · until "));
    }
}
