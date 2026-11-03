//! Alert detail panel: full alert view with ack, silence, and resolve forms.

use leptos::prelude::*;

use super::{severity_badge, state_label};
use crate::api::{ack_alert, create_silence, resolve_alert};
use crate::dto::{AlertState, AlertView, NewSilenceRequest, Silence};
use crate::state::{AppState, format_time_ms};

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

/// Detail panel for the selected alert, with ack/silence/resolve actions.
#[component]
pub(super) fn AlertDetail(
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

/// Refresh the detail panel and the list row after an ack/resolve. An
/// upsert, not a patch: the row may live only in paged history, and the
/// merged list prefers the shared copy — inserting keeps it fresh.
fn patch_alert(
    alerts: &RwSignal<Vec<AlertView>>,
    detail: &RwSignal<Option<AlertView>>,
    updated: AlertView,
) {
    detail.set(Some(updated.clone()));
    alerts.update(|list| {
        if let Some(existing) = list.iter_mut().find(|item| item.id == updated.id) {
            *existing = updated;
        } else {
            list.insert(0, updated);
            list.truncate(super::super::shell::MAX_ALERTS);
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
                    leptos::task::spawn_local(async move {
                        match create_silence(&token, &rule).await {
                            Ok(created) => {
                                silences.update(|rules| rules.insert(0, created));
                                detail.update(|current| {
                                    if let Some(view) = current {
                                        view.silenced = true;
                                    }
                                });
                                // Upsert, not patch: the row may live only
                                // in paged history, and the merged list
                                // prefers the shared copy.
                                if let Some(view) = detail.get_untracked() {
                                    alerts.update(|list| {
                                        if let Some(existing) =
                                            list.iter_mut().find(|item| item.id == view.id)
                                        {
                                            *existing = view;
                                        } else {
                                            list.insert(0, view);
                                            list.truncate(super::super::shell::MAX_ALERTS);
                                        }
                                    });
                                }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_ms_is_zero_off_wasm() {
        assert_eq!(now_ms(), 0);
    }
}
