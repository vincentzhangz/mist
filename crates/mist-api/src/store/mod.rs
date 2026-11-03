//! Flow and alert storage: Postgres for production, in-memory for tests
//! and DB-less development. Selected by `Store` at startup.

mod mem;
pub(crate) mod model;
mod pg;

pub use mem::MemStore;
pub(crate) use model::now_ms;
pub use model::{
    AlertFilter, AlertView, AlertsPage, FlowFilter, FlowsPage, NewSilence, Silence, silence_matches,
};
pub use pg::PgStore;

use mist_types::{Alert, FlowRecord};

#[derive(Clone)]
pub enum Store {
    Postgres(PgStore),
    Memory(MemStore),
}

impl Store {
    pub async fn save_flows(&self, flows: &[FlowRecord]) -> anyhow::Result<()> {
        match self {
            Self::Postgres(store) => store.save_flows(flows).await,
            Self::Memory(store) => store.save_flows(flows),
        }
    }

    pub async fn upsert_alert(&self, alert: &Alert) -> anyhow::Result<AlertView> {
        match self {
            Self::Postgres(store) => store.upsert_alert(alert).await,
            Self::Memory(store) => store.upsert_alert(alert),
        }
    }

    pub async fn resolve_alert(&self, id: &str) -> anyhow::Result<Option<AlertView>> {
        match self {
            Self::Postgres(store) => store.resolve_alert(id).await,
            Self::Memory(store) => store.resolve_alert(id),
        }
    }

    /// Acknowledge a firing alert as `by` with `note`. Returns `None` when
    /// the alert is missing or already resolved.
    pub async fn ack_alert(
        &self,
        id: &str,
        by: &str,
        note: &str,
    ) -> anyhow::Result<Option<AlertView>> {
        match self {
            Self::Postgres(store) => store.ack_alert(id, by, note).await,
            Self::Memory(store) => store.ack_alert(id, by, note),
        }
    }

    /// Store a silence rule, pruning expired ones first.
    pub async fn create_silence(&self, rule: &NewSilence) -> anyhow::Result<Silence> {
        match self {
            Self::Postgres(store) => store.create_silence(rule).await,
            Self::Memory(store) => store.create_silence(rule),
        }
    }

    /// All silence rules, earliest expiry first.
    pub async fn list_silences(&self) -> anyhow::Result<Vec<Silence>> {
        match self {
            Self::Postgres(store) => store.list_silences().await,
            Self::Memory(store) => store.list_silences(),
        }
    }

    /// Delete a silence rule. Returns whether one existed.
    pub async fn delete_silence(&self, id: i64) -> anyhow::Result<bool> {
        match self {
            Self::Postgres(store) => store.delete_silence(id).await,
            Self::Memory(store) => store.delete_silence(id),
        }
    }

    pub async fn list_flows(&self, filter: &FlowFilter) -> anyhow::Result<Vec<FlowRecord>> {
        match self {
            Self::Postgres(store) => store.list_flows(filter).await,
            Self::Memory(store) => store.list_flows(filter),
        }
    }

    pub async fn list_alerts(&self, filter: &AlertFilter) -> anyhow::Result<Vec<AlertView>> {
        match self {
            Self::Postgres(store) => store.list_alerts(filter).await,
            Self::Memory(store) => store.list_alerts(filter),
        }
    }

    pub async fn get_alert(&self, id: &str) -> anyhow::Result<Option<AlertView>> {
        match self {
            Self::Postgres(store) => store.get_alert(id).await,
            Self::Memory(store) => store.get_alert(id),
        }
    }

    /// Live storage gauges for the `/metrics` scrape.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage backend fails.
    pub async fn counts(&self) -> anyhow::Result<crate::metrics::StoreCounts> {
        match self {
            Self::Postgres(store) => store.counts().await,
            Self::Memory(store) => store.counts(),
        }
    }

    /// Insert or replace the password hash for `email`.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage backend fails.
    pub async fn upsert_user(&self, email: &str, password_hash: &str) -> anyhow::Result<()> {
        match self {
            Self::Postgres(store) => store.upsert_user(email, password_hash).await,
            Self::Memory(store) => store.upsert_user(email, password_hash),
        }
    }

    /// Fetch the stored password hash for `email`, if the user exists.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage backend fails.
    pub async fn get_password_hash(&self, email: &str) -> anyhow::Result<Option<String>> {
        match self {
            Self::Postgres(store) => store.get_password_hash(email).await,
            Self::Memory(store) => store.get_password_hash(email),
        }
    }
}
