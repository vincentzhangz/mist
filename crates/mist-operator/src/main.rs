//! mist-operator: Kubernetes controller for mist.
//!
//! Reconciles `TrafficMonitor` resources into the agent `DaemonSet` and mirrors
//! analyzer findings posted to the alert webhook as `AnomalyAlert` resources.

mod crd;
mod reconcile;
mod webhook;

use std::{net::SocketAddr, sync::Arc};

use clap::Parser;
use futures::StreamExt as _;
use k8s_openapi::api::apps::v1::DaemonSet;
use kube::{
    Client, CustomResourceExt as _,
    api::Api,
    runtime::{Controller, watcher},
};
use tracing_subscriber::EnvFilter;

use crate::{
    crd::{AnomalyAlert, TrafficMonitor},
    reconcile::{Context, error_policy, reconcile},
};

#[derive(Debug, Parser)]
#[command(name = "mist-operator")]
struct Args {
    /// Namespace to watch for `TrafficMonitor` objects (alerts land here too).
    #[arg(long, env = "OPERATOR_NAMESPACE", default_value = "mist")]
    namespace: String,
    /// Address for the alert webhook.
    #[arg(long, default_value = "0.0.0.0:8081")]
    webhook_addr: SocketAddr,
    /// Print CRD manifests as YAML and exit.
    #[arg(long)]
    print_crds: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    let args = Args::parse();
    if args.print_crds {
        println!("---");
        println!("{}", serde_yaml::to_string(&TrafficMonitor::crd())?);
        println!("---");
        println!("{}", serde_yaml::to_string(&AnomalyAlert::crd())?);
        return Ok(());
    }

    let client = Client::try_default().await?;
    let ctx = Arc::new(Context {
        client: client.clone(),
        namespace: args.namespace.clone(),
    });
    let monitors: Api<TrafficMonitor> = Api::namespaced(client.clone(), &args.namespace);
    let daemonsets: Api<DaemonSet> = Api::namespaced(client.clone(), &args.namespace);

    let drive_controller = Controller::new(monitors, watcher::Config::default())
        .owns(daemonsets, watcher::Config::default())
        .run(reconcile, error_policy, ctx)
        .for_each(|result| async {
            match result {
                Ok(_) => {}
                // Expected when a watched object is deleted mid-reconcile.
                Err(kube::runtime::controller::Error::ObjectNotFound(_)) => {
                    tracing::debug!("scheduled reconcile for deleted object; skipping");
                }
                Err(error) => tracing::warn!(?error, "controller stream error"),
            }
        });

    let app = webhook::router(webhook::WebhookState {
        client,
        namespace: args.namespace,
    });
    let listener = tokio::net::TcpListener::bind(args.webhook_addr).await?;
    tracing::info!(addr = %args.webhook_addr, "alert webhook listening");
    let serve_webhook = axum::serve(listener, app);

    tokio::select! {
        () = drive_controller => {
            tracing::warn!("controller stream ended");
            Ok(())
        }
        result = serve_webhook => {
            result?;
            tracing::warn!("webhook server ended");
            Ok(())
        }
    }
}
