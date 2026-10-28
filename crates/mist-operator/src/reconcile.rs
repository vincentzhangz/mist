//! Reconcile loop: render the agent `DaemonSet` from the oldest
//! `TrafficMonitor` in the operator namespace.

use std::{sync::Arc, time::Duration};

use anyhow::Context as _;
use k8s_openapi::api::apps::v1::DaemonSet;
use kube::{
    Resource as _, ResourceExt as _,
    api::{Api, DeleteParams, ListParams, Patch, PatchParams},
    runtime::controller::Action,
};
use serde_json::json;

use crate::crd::{MonitorState, TrafficMonitor, TrafficMonitorStatus};

pub const DAEMONSET_NAME: &str = "mist-agent";
pub const FIELD_MANAGER: &str = "mist-operator";

#[derive(Clone)]
pub struct Context {
    pub client: kube::Client,
    pub namespace: String,
}

/// Typed reconcile error: `Controller::run` requires `std::error::Error`.
#[derive(Debug, thiserror::Error)]
pub enum ReconcileError {
    #[error("kubernetes error: {0}")]
    Kube(#[from] kube::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub async fn reconcile(
    monitor: Arc<TrafficMonitor>,
    ctx: Arc<Context>,
) -> Result<Action, ReconcileError> {
    let monitors: Api<TrafficMonitor> = Api::namespaced(ctx.client.clone(), &ctx.namespace);
    let owned: Api<DaemonSet> = Api::namespaced(ctx.client.clone(), &ctx.namespace);
    let list = monitors.list(&ListParams::default()).await?;
    let Some(active) = pick_oldest(&list.items) else {
        delete_daemonset_if_exists(&owned).await?;
        return Ok(Action::await_change());
    };
    let active_name = active.name_any();
    for other in &list.items {
        if other.name_any() != active_name {
            set_state(
                &monitors,
                other,
                MonitorState::Superseded,
                format!("superseded by {active_name}"),
            )
            .await?;
        }
    }
    if monitor.name_any() != active_name {
        return Ok(Action::await_change());
    }
    let desired = desired_daemonset(active, &active_name)?;
    owned
        .patch(
            DAEMONSET_NAME,
            &PatchParams::apply(FIELD_MANAGER),
            &Patch::Apply(&desired),
        )
        .await?;
    set_state(
        &monitors,
        active,
        MonitorState::Ready,
        "DaemonSet applied".to_owned(),
    )
    .await?;
    Ok(Action::await_change())
}

pub fn error_policy(
    _monitor: Arc<TrafficMonitor>,
    error: &ReconcileError,
    _ctx: Arc<Context>,
) -> Action {
    tracing::warn!(?error, "reconcile failed; retrying in 60s");
    Action::requeue(Duration::from_secs(60))
}

/// Oldest instance wins (creation timestamp, then name). Deterministic under
/// concurrent creates; a replacement takes over only after the active one is
/// deleted.
pub fn pick_oldest(monitors: &[TrafficMonitor]) -> Option<&TrafficMonitor> {
    monitors.iter().min_by(|a, b| {
        a.metadata
            .creation_timestamp
            .cmp(&b.metadata.creation_timestamp)
            .then_with(|| a.name_any().cmp(&b.name_any()))
    })
}

async fn delete_daemonset_if_exists(owned: &Api<DaemonSet>) -> Result<(), ReconcileError> {
    match owned.delete(DAEMONSET_NAME, &DeleteParams::default()).await {
        Ok(_) => {
            tracing::info!("removed DaemonSet (no TrafficMonitor left)");
            Ok(())
        }
        Err(kube::Error::Api(api_error)) if api_error.code == 404 => Ok(()),
        Err(error) => Err(error.into()),
    }
}

async fn set_state(
    monitors: &Api<TrafficMonitor>,
    monitor: &TrafficMonitor,
    state: MonitorState,
    message: String,
) -> Result<(), ReconcileError> {
    let status = TrafficMonitorStatus {
        state,
        message: Some(message),
        observed_generation: monitor.metadata.generation,
    };
    monitors
        .patch_status(
            &monitor.name_any(),
            &PatchParams::default(),
            &Patch::Merge(json!({ "status": status })),
        )
        .await?;
    Ok(())
}

/// Build the agent `DaemonSet` for a monitor. The shape is pinned by the golden
/// fixture at `testdata/agent-daemonset.yaml`; update both together.
pub fn desired_daemonset(
    monitor: &TrafficMonitor,
    monitor_name: &str,
) -> Result<DaemonSet, ReconcileError> {
    let spec = &monitor.spec;
    let owner = monitor
        .controller_owner_ref(&())
        .context("monitor has no UID for owner reference")?;
    let watched = spec.watched_namespaces.join(",");
    // Hardening is deliberately partial here: the agent keeps
    // `hostNetwork` + `privileged` because loading TC eBPF programs needs
    // `CAP_BPF`/`CAP_NET_ADMIN` semantics, so only `resources` and a pod-level
    // seccomp profile are pinned. Keep the golden fixture in sync.
    let mut daemonset: DaemonSet = serde_json::from_value(json!({
        "apiVersion": "apps/v1",
        "kind": "DaemonSet",
        "metadata": {
            "name": DAEMONSET_NAME,
            "labels": {
                "app.kubernetes.io/name": "mist-agent",
                "app.kubernetes.io/part-of": "mist",
                "mist.io/monitor": monitor_name,
            },
        },
        "spec": {
            "selector": { "matchLabels": { "app.kubernetes.io/name": "mist-agent" } },
            "template": {
                "metadata": {
                    "labels": {
                        "app.kubernetes.io/name": "mist-agent",
                        "app.kubernetes.io/part-of": "mist",
                    },
                },
                "spec": {
                    "serviceAccountName": "mist-agent",
                    "hostNetwork": true,
                    "dnsPolicy": "ClusterFirstWithHostNet",
                    "securityContext": { "seccompProfile": { "type": "RuntimeDefault" } },
                    "nodeSelector": spec.node_selector,
                    "tolerations": [{ "operator": "Exists" }],
                    "containers": [{
                        "name": "agent",
                        "image": spec.agent_image,
                        "imagePullPolicy": "IfNotPresent",
                        "securityContext": { "privileged": true },
                        "env": [
                            { "name": "NODE_NAME", "valueFrom": { "fieldRef": { "fieldPath": "spec.nodeName" } } },
                            { "name": "RUST_LOG", "value": "info" },
                            { "name": "MIST_WATCHED_NAMESPACES", "value": watched },
                        ],
                        "args": [
                            format!("--object={}", spec.object_path),
                            format!("--api-url={}", spec.api_url),
                            format!("--interval-secs={}", spec.sample_interval_secs),
                        ],
                        "volumeMounts": [
                            { "name": "sys", "mountPath": "/sys", "readOnly": true },
                        ],
                        "resources": {
                            "requests": { "cpu": "50m", "memory": "64Mi" },
                            "limits": { "cpu": "1", "memory": "256Mi" },
                        },
                    }],
                    "volumes": [{ "name": "sys", "hostPath": { "path": "/sys" } }],
                },
            },
        },
    }))?;
    daemonset.meta_mut().owner_references = Some(vec![owner]);
    Ok(daemonset)
}

#[cfg(test)]
mod tests {
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, Time};

    use crate::crd::TrafficMonitorSpec;

    use super::*;

    fn monitor_with(name: &str, created: &str) -> TrafficMonitor {
        TrafficMonitor {
            metadata: ObjectMeta {
                name: Some(name.to_owned()),
                uid: Some(format!("uid-{name}")),
                creation_timestamp: Some(serde_json::from_value(json!(created)).unwrap()),
                ..Default::default()
            },
            spec: TrafficMonitorSpec::default(),
            status: None,
        }
    }

    #[test]
    fn picks_oldest_then_name() {
        assert!(pick_oldest(&[]).is_none());
        let monitors = vec![
            monitor_with("newer", "2026-10-28T10:00:00Z"),
            monitor_with("older", "2026-10-28T09:00:00Z"),
            monitor_with("aaa", "2026-10-28T09:00:00Z"),
        ];
        assert_eq!(pick_oldest(&monitors).unwrap().name_any(), "aaa");
        let monitors = vec![
            monitor_with("newer", "2026-10-28T10:00:00Z"),
            monitor_with("older", "2026-10-28T09:00:00Z"),
        ];
        assert_eq!(pick_oldest(&monitors).unwrap().name_any(), "older");
    }

    #[test]
    fn desired_daemonset_reflects_spec() {
        let monitor = TrafficMonitor {
            metadata: ObjectMeta {
                name: Some("custom".to_owned()),
                uid: Some("uid-custom".to_owned()),
                ..Default::default()
            },
            spec: TrafficMonitorSpec {
                agent_image: "registry.example/mist-agent:v2".to_owned(),
                api_url: "http://api:9999".to_owned(),
                sample_interval_secs: 30,
                watched_namespaces: vec!["prod".to_owned(), "staging".to_owned()],
                node_selector: [("disk".to_owned(), "ssd".to_owned())]
                    .into_iter()
                    .collect(),
                ..TrafficMonitorSpec::default()
            },
            status: None,
        };
        let daemonset = desired_daemonset(&monitor, "custom").unwrap();
        let value = serde_json::to_value(&daemonset).unwrap();
        let container = &value["spec"]["template"]["spec"]["containers"][0];
        assert_eq!(container["image"], "registry.example/mist-agent:v2");
        assert_eq!(
            container["args"],
            json!([
                "--object=/etc/mist/mist-ebpf.o",
                "--api-url=http://api:9999",
                "--interval-secs=30",
            ])
        );
        assert_eq!(
            value["spec"]["template"]["spec"]["nodeSelector"],
            json!({ "disk": "ssd" })
        );
        let env = container["env"].as_array().unwrap();
        let watched = env
            .iter()
            .find(|entry| entry["name"] == "MIST_WATCHED_NAMESPACES")
            .unwrap();
        assert_eq!(watched["value"], "prod,staging");
        // Owner reference points back at the monitor as controller.
        let owners = value["metadata"]["ownerReferences"].as_array().unwrap();
        assert_eq!(owners.len(), 1);
        assert_eq!(owners[0]["controller"], true);
        assert_eq!(owners[0]["kind"], "TrafficMonitor");
        assert_eq!(owners[0]["name"], "custom");
        assert_eq!(owners[0]["uid"], "uid-custom");
        assert_eq!(value["metadata"]["labels"]["mist.io/monitor"], "custom");
    }

    /// The rendered `DaemonSet` must match the golden fixture (minus
    /// cluster-assigned fields), so YAML and code cannot drift apart.
    #[test]
    fn matches_golden_fixture() {
        let fixture: serde_json::Value =
            serde_yaml::from_str(include_str!("../testdata/agent-daemonset.yaml")).unwrap();
        let monitor = monitor_with("default", "2026-10-28T09:00:00Z");
        let mut rendered =
            serde_json::to_value(desired_daemonset(&monitor, "default").unwrap()).unwrap();
        let meta = rendered["metadata"].as_object_mut().unwrap();
        meta.remove("ownerReferences");
        meta["labels"]
            .as_object_mut()
            .unwrap()
            .remove("mist.io/monitor");
        let mut expected = fixture;
        expected.as_object_mut().unwrap().remove("status");
        expected["metadata"]
            .as_object_mut()
            .unwrap()
            .remove("namespace");
        assert_eq!(rendered, expected);
    }

    #[test]
    fn time_compares_chronologically() {
        // Guard for `pick_oldest`: k8s Time orders by instant, not string.
        let earlier: Time = serde_json::from_value(json!("2026-10-28T09:00:00Z")).unwrap();
        let later: Time = serde_json::from_value(json!("2026-10-28T10:00:00Z")).unwrap();
        assert!(earlier < later);
    }
}
