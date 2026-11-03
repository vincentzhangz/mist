//! Policies view: namespace `NetworkPolicy` recommendations generated
//! from observed external traffic, with ready-to-review YAML.

use leptos::prelude::*;

use crate::api::fetch_recommendation;
use crate::dto::{DnsRule, PolicyRecommendation, UncoveredPod, WorkloadPolicy};
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
                "Per-workload recommendations from observed external traffic. \
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
    let policies = rec.workload_policies.clone();
    let uncovered = rec.uncovered.clone();
    // Eager: the recommendation is a one-shot snapshot, not live data.
    let has_policies = !policies.is_empty();
    let has_uncovered = !uncovered.is_empty();
    view! {
        <div>
            <p class="muted">
                {format!(
                    "Analyzed {} flows ({} internal-only, {} DNS, {} unsupported) · workloads: {}",
                    rec.flows_analyzed,
                    rec.internal_flows,
                    rec.dns_flows,
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
            <p class="muted">
                {format!(
                    "{} workload policies · {} uncovered pods",
                    policies.len(),
                    uncovered.len(),
                )}
            </p>
            <Show when=move || has_policies>
                <WorkloadList policies=policies.clone() />
            </Show>
            <Show when=move || has_uncovered>
                <UncoveredList uncovered=uncovered.clone() />
            </Show>
            <pre class="yaml">{rec.yaml.clone()}</pre>
        </div>
    }
}

/// One-line summary of a workload's DNS allows, or `None` when bare.
fn dns_summary(policy: &WorkloadPolicy) -> Option<String> {
    if policy.dns_egress.is_empty() {
        return None;
    }
    let parts: Vec<String> = policy
        .dns_egress
        .iter()
        .map(|rule: &DnsRule| match (&rule.namespace, &rule.cidr) {
            (Some(ns), _) => {
                let selector: Vec<String> = rule
                    .pod_selector
                    .iter()
                    .map(|(key, value)| format!("{key}={value}"))
                    .collect();
                format!("{ns}/{}", selector.join(","))
            }
            (None, Some(cidr)) => cidr.clone(),
            (None, None) => rule.servers.join(","),
        })
        .collect();
    Some(format!("DNS: {}", parts.join("; ")))
}

/// Per-workload policies: name, covered pods, selector chips, rule counts.
#[component]
fn WorkloadList(policies: Vec<WorkloadPolicy>) -> impl IntoView {
    view! {
        <h3>"Workloads"</h3>
        <For
            each=move || policies.clone()
            key=|policy| policy.workload.clone()
            let(policy)
        >
            <WorkloadRow policy=policy />
        </For>
    }
}

/// One workload row plus its optional DNS line.
#[component]
fn WorkloadRow(policy: WorkloadPolicy) -> impl IntoView {
    let dns = dns_summary(&policy);
    view! {
        <p>
            <span class="mono">{policy.workload.clone()}</span>
            " · "
            <span class="muted">{policy.pods.join(", ")}</span>
        </p>
        <p>
            <For
                each={
                    let selector = policy.selector.clone();
                    move || selector.clone().into_iter().collect::<Vec<_>>()
                }
                key=|pair| pair.0.clone()
                let(pair)
            >
                <span class="chip">{format!("{}={}", pair.0, pair.1)}</span>
                " "
            </For>
            <span class="muted">
                {format!(
                    "{} egress · {} ingress CIDRs",
                    policy.external_egress.len(),
                    policy.external_ingress.len(),
                )}
            </span>
        </p>
        {dns.map(|text| {
            view! {
                <p>
                    <span class="muted">{text}</span>
                </p>
            }
        })}
    }
}

/// Pods with external traffic but no usable labels.
#[component]
fn UncoveredList(uncovered: Vec<UncoveredPod>) -> impl IntoView {
    view! {
        <h3>"Uncovered pods"</h3>
        <For
            each=move || uncovered.clone()
            key=|item| item.pod.clone()
            let(item)
        >
            <p>
                <span class="mono">{item.pod.clone()}</span>
                " — "
                <span class="muted">{item.reason.clone()}</span>
            </p>
        </For>
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
                "external_ingress":[],
                "workload_policies":[{"workload":"web-observed",
                "selector":{"app":"web"},"pods":["web-0"],
                "external_egress":[{"cidr":"8.8.8.8/32",
                "ports":[{"port":53,"protocol":"UDP"}]}],
                "external_ingress":[]}],
                "uncovered":[{"pod":"bare-0","reason":"no labels"}],
                "yaml":"kind: NetworkPolicy"}"#,
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
        assert_eq!(rec.workload_policies.len(), 1);
        assert_eq!(rec.workload_policies[0].workload, "web-observed");
        assert_eq!(
            rec.workload_policies[0]
                .selector
                .get("app")
                .map(String::as_str),
            Some("web")
        );
        assert_eq!(rec.uncovered.len(), 1);
        // Payloads from older APIs omit the per-workload keys.
        let legacy: PolicyRecommendation = serde_json::from_str(
            r#"{"namespace":"default","flows_analyzed":10,"internal_flows":9,
                "unsupported_flows":0,"workloads":["web"],
                "external_egress":[],"external_ingress":[],
                "yaml":"kind: NetworkPolicy"}"#,
        )
        .expect("must parse");
        assert_eq!(legacy.workload_policies.len(), 0);
        assert_eq!(legacy.uncovered.len(), 0);
        assert_eq!(legacy.dns_flows, 0);
    }

    #[test]
    fn dns_summary_renders_both_rule_kinds() {
        let selector = |namespace: Option<&str>, cidr: Option<&str>| WorkloadPolicy {
            workload: "web-observed".to_owned(),
            selector: std::collections::BTreeMap::new(),
            pods: vec!["web-0".to_owned()],
            external_egress: Vec::new(),
            external_ingress: Vec::new(),
            dns_egress: vec![DnsRule {
                namespace: namespace.map(str::to_owned),
                pod_selector: std::collections::BTreeMap::from([(
                    "k8s-app".to_owned(),
                    "kube-dns".to_owned(),
                )]),
                cidr: cidr.map(str::to_owned),
                servers: vec!["10.96.0.10".to_owned()],
            }],
        };
        let bare = WorkloadPolicy {
            dns_egress: Vec::new(),
            ..selector(None, None)
        };
        assert_eq!(dns_summary(&bare), None);
        // Degenerate rule with no target falls back to server IPs.
        assert_eq!(
            dns_summary(&selector(None, None)).as_deref(),
            Some("DNS: 10.96.0.10")
        );
        assert_eq!(
            dns_summary(&selector(Some("kube-system"), None)).as_deref(),
            Some("DNS: kube-system/k8s-app=kube-dns")
        );
        assert_eq!(
            dns_summary(&selector(None, Some("10.96.0.10/32"))).as_deref(),
            Some("DNS: 10.96.0.10/32")
        );
    }
}
