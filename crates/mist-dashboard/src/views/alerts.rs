//! Alerts view: filterable list + detail panel with ack, silence, and
//! resolve actions.

use leptos::prelude::*;

use crate::api::{
    ack_alert, create_silence, delete_silence, fetch_alert, fetch_alerts, fetch_silences,
    resolve_alert,
};
use crate::dto::{AlertState, AlertView, NewSilenceRequest, Severity, Silence};
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

/// Wall-clock unix millis in the browser (0 on non-wasm targets).
fn now_ms() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        #[allow(clippy::cast_possible_truncation)]
        return js_sys::Date::now() as u64;
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        0
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
    let query = RwSignal::new(String::new());
    let filtered = Memo::new(move |_| filter_alerts(&state.alerts.get(), &query.get()));
    let silences = RwSignal::new(Vec::<Silence>::new());

    load_alerts_data(
        state,
        severity_filter,
        state_filter,
        silences,
        list_error,
        list_loaded,
    );

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
                        silences=silences
                    />
                </div>
            </div>
        </section>
    }
}

/// Fetch effects for the alert list (refetched on token/filter change)
/// and the silence rules (once per session).
fn load_alerts_data(
    state: AppState,
    severity_filter: RwSignal<String>,
    state_filter: RwSignal<String>,
    silences: RwSignal<Vec<Silence>>,
    list_error: RwSignal<Option<String>>,
    list_loaded: RwSignal<bool>,
) {
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
                    list_error.set(Some(err.to_string()));
                }
            }
        });
    });
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

/// Detail panel for the selected alert, with ack/silence/resolve actions.
#[component]
fn AlertDetail(
    detail: RwSignal<Option<AlertView>>,
    loading: RwSignal<bool>,
    error: RwSignal<Option<String>>,
    silences: RwSignal<Vec<Silence>>,
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
                                        silences=silences
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

/// Refresh the detail panel and the list row after an ack/resolve.
fn patch_alert(
    alerts: &RwSignal<Vec<AlertView>>,
    detail: &RwSignal<Option<AlertView>>,
    updated: AlertView,
) {
    detail.set(Some(updated.clone()));
    alerts.update(|list| {
        if let Some(existing) = list.iter_mut().find(|item| item.id == updated.id) {
            *existing = updated;
        }
    });
}

/// The loaded alert article (title, explanation, labels, action forms).
#[component]
fn AlertBody(
    alert: AlertView,
    detail: RwSignal<Option<AlertView>>,
    error: RwSignal<Option<String>>,
    silences: RwSignal<Vec<Silence>>,
    state: AppState,
) -> impl IntoView {
    let (sev_label, sev_class) = severity_badge(alert.severity);
    let is_firing = alert.state == AlertState::Firing;
    let is_open = matches!(alert.state, AlertState::Firing | AlertState::Acknowledged);
    let silenced = alert.silenced;
    let acked_by = alert.acked_by.clone();
    let ack_note = alert.ack_note.clone();
    let show_ack = acked_by.is_some();
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
            <Show when=move || silenced>
                <p>
                    <span class="chip">"muted by a silence rule"</span>
                </p>
            </Show>
            <Show when=move || show_ack>
                <p class="muted">
                    {format!("Acked by {}", acked_by.clone().unwrap_or_default())}
                    {ack_note
                        .clone()
                        .filter(|note| !note.is_empty())
                        .map(|note| format!(" — {note}"))}
                </p>
            </Show>
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
                <AckForm detail=detail session=state error=error />
            </Show>
            <Show when=move || is_open>
                <SilenceForm
                    alert_id=alert.id.clone()
                    detail=detail
                    silences=silences
                    session=state
                    error=error
                />
                <ResolveForm detail=detail session=state error=error />
            </Show>
        </article>
    }
}

/// Ack form: optional note + button, shown while the alert is firing.
#[component]
fn AckForm(
    detail: RwSignal<Option<AlertView>>,
    session: AppState,
    error: RwSignal<Option<String>>,
) -> impl IntoView {
    let note = RwSignal::new(String::new());
    let busy = RwSignal::new(false);
    view! {
        <div class="action-row">
            <input
                type="text"
                placeholder="Ack note (optional)"
                spellcheck="false"
                autocomplete="off"
                on:input=move |ev| {
                    note.set(event_target_value(&ev));
                }
                prop:value=move || note.get()
            />
            <button
                class="btn-ghost"
                on:click=move |_| {
                    let (Some(token), Some(current)) = (
                        session.token.get_untracked(),
                        detail.get_untracked(),
                    ) else {
                        return;
                    };
                    if busy.get_untracked() {
                        return;
                    }
                    busy.set(true);
                    error.set(None);
                    let note = note.get_untracked().trim().to_owned();
                    let alerts = session.alerts;
                    leptos::task::spawn_local(async move {
                        let note = (!note.is_empty()).then_some(note);
                        match ack_alert(&token, &current.id, note).await {
                            Ok(updated) => patch_alert(&alerts, &detail, updated),
                            Err(err) => {
                                session.logout_if_unauthorized(&err);
                                error.set(Some(err.to_string()));
                            }
                        }
                        busy.set(false);
                    });
                }
                disabled=move || busy.get()
            >
                {move || if busy.get() { "Acking…" } else { "Ack" }}
            </button>
        </div>
    }
}

/// Silence form: mute this alert id for a chosen duration.
#[component]
fn SilenceForm(
    alert_id: String,
    detail: RwSignal<Option<AlertView>>,
    silences: RwSignal<Vec<Silence>>,
    session: AppState,
    error: RwSignal<Option<String>>,
) -> impl IntoView {
    const DURATIONS: [(&str, u64); 3] = [
        ("1 hour", 3_600_000),
        ("24 hours", 86_400_000),
        ("7 days", 604_800_000),
    ];
    let duration = RwSignal::new(86_400_000_u64);
    let busy = RwSignal::new(false);
    view! {
        <div class="action-row">
            <select
                on:change=move |ev| {
                    duration.set(event_target_value(&ev).parse().unwrap_or(86_400_000));
                }
                prop:value=move || duration.get().to_string()
                aria-label="Silence duration"
            >
                {DURATIONS
                    .into_iter()
                    .map(|(label, ms)| {
                        view! { <option value=ms.to_string()>{label}</option> }
                    })
                    .collect::<Vec<_>>()}
            </select>
            <button
                class="btn-ghost"
                on:click=move |_| {
                    let Some(token) = session.token.get_untracked() else {
                        return;
                    };
                    if busy.get_untracked() {
                        return;
                    }
                    busy.set(true);
                    error.set(None);
                    let rule = NewSilenceRequest {
                        severity: None,
                        title_contains: None,
                        alert_id: Some(alert_id.clone()),
                        label_key: None,
                        label_value: None,
                        starts_at_ms: None,
                        ends_at_ms: now_ms().saturating_add(duration.get_untracked()),
                        comment: None,
                    };
                    let alerts = session.alerts;
                    let muted_id = alert_id.clone();
                    leptos::task::spawn_local(async move {
                        match create_silence(&token, &rule).await {
                            Ok(created) => {
                                silences.update(|rules| rules.insert(0, created));
                                detail.update(|current| {
                                    if let Some(view) = current {
                                        view.silenced = true;
                                    }
                                });
                                alerts.update(|list| {
                                    if let Some(existing) = list
                                        .iter_mut()
                                        .find(|item| item.id == muted_id)
                                    {
                                        existing.silenced = true;
                                    }
                                });
                            }
                            Err(err) => {
                                session.logout_if_unauthorized(&err);
                                error.set(Some(err.to_string()));
                            }
                        }
                        busy.set(false);
                    });
                }
                disabled=move || busy.get()
            >
                {move || if busy.get() { "Muting…" } else { "Mute" }}
            </button>
        </div>
    }
}

/// Resolve button for open (firing or acknowledged) alerts.
#[component]
fn ResolveForm(
    detail: RwSignal<Option<AlertView>>,
    session: AppState,
    error: RwSignal<Option<String>>,
) -> impl IntoView {
    let busy = RwSignal::new(false);
    view! {
        <div class="action-row">
            <button
                on:click=move |_| {
                    let (Some(token), Some(current)) = (
                        session.token.get_untracked(),
                        detail.get_untracked(),
                    ) else {
                        return;
                    };
                    if busy.get_untracked() {
                        return;
                    }
                    busy.set(true);
                    error.set(None);
                    let alerts = session.alerts;
                    leptos::task::spawn_local(async move {
                        match resolve_alert(&token, &current.id).await {
                            Ok(updated) => patch_alert(&alerts, &detail, updated),
                            Err(err) => {
                                session.logout_if_unauthorized(&err);
                                error.set(Some(err.to_string()));
                            }
                        }
                        busy.set(false);
                    });
                }
                disabled=move || busy.get()
            >
                {move || if busy.get() { "Resolving…" } else { "Resolve" }}
            </button>
        </div>
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

    #[test]
    fn now_ms_is_zero_off_wasm() {
        assert_eq!(now_ms(), 0);
    }
}
