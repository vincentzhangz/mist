//! Policies view: namespace `NetworkPolicy` recommendations generated
//! from observed external traffic, with ready-to-review YAML.

use leptos::prelude::*;

use crate::api::fetch_recommendation;
use crate::dto::PolicyRecommendation;
use crate::state::AppState;

/// Policies page: namespace picker + generated recommendation.
#[component]
pub fn PoliciesView() -> impl IntoView {
    let state = expect_context::<AppState>();
    let namespace = RwSignal::new("default".to_owned());
    let result = RwSignal::new(Option::<PolicyRecommendation>::None);
    let loading = RwSignal::new(false);
    let error = RwSignal::new(Option::<String>::None);

    // Generate for the default namespace on first load.
    Effect::new(move || {
        if state.token.get().is_some() && result.get_untracked().is_none() {
            generate(state, namespace, result, loading, error);
        }
    });

    view! {
        <section class="policies">
            <h2>"Policies"</h2>
            <p class="muted">
                "Namespace-wide recommendations from observed external traffic. \
                 Review before applying."
            </p>
            <div class="filters">
                <label>
                    "Namespace"
                    <input
                        type="text"
                        placeholder="default"
                        spellcheck="false"
                        autocomplete="off"
                        on:input=move |ev| {
                            namespace.set(event_target_value(&ev));
                        }
                        prop:value=move || namespace.get()
                    />
                </label>
                <button
                    on:click=move |_| {
                        generate(state, namespace, result, loading, error);
                    }
                    disabled=move || loading.get()
                >
                    {move || if loading.get() { "Generating…" } else { "Generate" }}
                </button>
            </div>
            <Show when=move || error.get().is_some()>
                <p class="error" aria-live="polite">
                    {move || error.get().unwrap_or_default()}
                </p>
            </Show>
            <Show
                when=move || result.get().is_some()
                fallback=move || {
                    view! {
                        <Show when=move || loading.get()>
                            <p class="muted">"Generating recommendation…"</p>
                        </Show>
                    }
                }
            >
                {move || {
                    result.get().map(|rec| {
                        view! { <PolicyResult rec=rec /> }
                    })
                }}
            </Show>
        </section>
    }
}

/// Fetch a recommendation for the current namespace input.
fn generate(
    state: AppState,
    namespace: RwSignal<String>,
    result: RwSignal<Option<PolicyRecommendation>>,
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
    let name = namespace.get_untracked();
    let session = state;
    leptos::task::spawn_local(async move {
        match fetch_recommendation(&token, &name).await {
            Ok(rec) => {
                result.set(Some(rec));
            }
            Err(err) => {
                session.logout_if_unauthorized(&err);
                error.set(Some(err.to_string()));
            }
        }
        loading.set(false);
    });
}

/// Recommendation summary plus the YAML preview.
#[component]
fn PolicyResult(rec: PolicyRecommendation) -> impl IntoView {
    let workloads = rec.workloads.join(", ");
    view! {
        <div>
            <p class="muted">
                {format!(
                    "Analyzed {} flows ({} internal-only, {} unsupported) · workloads: {}",
                    rec.flows_analyzed,
                    rec.internal_flows,
                    rec.unsupported_flows,
                    if workloads.is_empty() { "—".to_owned() } else { workloads },
                )}
            </p>
            <p class="muted">
                {format!(
                    "{} external egress CIDRs · {} external ingress CIDRs",
                    rec.external_egress.len(),
                    rec.external_ingress.len(),
                )}
            </p>
            <pre class="yaml">{rec.yaml.clone()}</pre>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::{CidrRule, PortRule};

    #[test]
    fn recommendation_shape_parses() {
        let rec: PolicyRecommendation = serde_json::from_str(
            r#"{"namespace":"default","flows_analyzed":10,"internal_flows":9,
                "unsupported_flows":0,"workloads":["web"],
                "external_egress":[{"cidr":"8.8.8.8/32",
                "ports":[{"port":53,"protocol":"UDP"}]}],
                "external_ingress":[],"yaml":"kind: NetworkPolicy"}"#,
        )
        .expect("must parse");
        assert_eq!(rec.namespace, "default");
        assert_eq!(
            rec.external_egress,
            vec![CidrRule {
                cidr: "8.8.8.8/32".to_owned(),
                ports: vec![PortRule {
                    port: 53,
                    protocol: "UDP".to_owned(),
                }],
            }]
        );
        assert_eq!(rec.external_ingress, Vec::new());
    }
}
