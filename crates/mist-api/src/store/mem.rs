//! In-memory storage backend (tests and DB-less development).

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use mist_types::{Alert, FlowRecord};

use super::model::{
    AlertFilter, AlertLifecycle, AlertView, FlowFilter, NewSilence, Silence, now_ms,
};

#[derive(Clone, Default)]
pub struct MemStore {
    inner: Arc<RwLock<MemState>>,
}

/// In-memory store cap: flow history beyond this is pruned oldest-first.
const MEM_FLOW_CAP: usize = 20_000;

#[derive(Default)]
struct MemState {
    flows: Vec<FlowRecord>,
    alerts: HashMap<String, StoredAlert>,
    users: HashMap<String, String>,
    silences: HashMap<i64, Silence>,
    next_silence_id: i64,
}

struct StoredAlert {
    alert: Alert,
    state: AlertLifecycle,
    occurrences: u64,
    acked_by: Option<String>,
    ack_note: Option<String>,
}

impl StoredAlert {
    fn view(&self) -> AlertView {
        AlertView {
            alert: self.alert.clone(),
            state: self.state,
            occurrences: self.occurrences,
            acked_by: self.acked_by.clone(),
            ack_note: self.ack_note.clone(),
            silenced: false,
        }
    }
}

impl MemStore {
    fn read(&self) -> anyhow::Result<std::sync::RwLockReadGuard<'_, MemState>> {
        self.inner
            .read()
            .map_err(|_| anyhow::anyhow!("mem store lock poisoned"))
    }

    fn write(&self) -> anyhow::Result<std::sync::RwLockWriteGuard<'_, MemState>> {
        self.inner
            .write()
            .map_err(|_| anyhow::anyhow!("mem store lock poisoned"))
    }
}

impl MemStore {
    pub(crate) fn save_flows(&self, flows: &[FlowRecord]) -> anyhow::Result<()> {
        let mut state = self.write()?;
        state.flows.extend_from_slice(flows);
        let overflow = state.flows.len().saturating_sub(MEM_FLOW_CAP);
        state.flows.drain(..overflow);
        Ok(())
    }

    pub(crate) fn upsert_alert(&self, alert: &Alert) -> anyhow::Result<AlertView> {
        let mut state = self.write()?;
        let stored = state
            .alerts
            .entry(alert.id.clone())
            .or_insert_with(|| StoredAlert {
                alert: alert.clone(),
                state: AlertLifecycle::Firing,
                occurrences: 0,
                acked_by: None,
                ack_note: None,
            });
        // A re-fire without an explanation (e.g. the stub explainer) keeps
        // the stored one; a re-fire carrying one refreshes it.
        let explanation = alert
            .explanation
            .clone()
            .or_else(|| stored.alert.explanation.clone());
        stored.alert = alert.clone();
        stored.alert.explanation = explanation;
        stored.alert.first_seen_unix_ms = stored
            .alert
            .first_seen_unix_ms
            .min(alert.first_seen_unix_ms);
        stored.alert.last_seen_unix_ms =
            stored.alert.last_seen_unix_ms.max(alert.last_seen_unix_ms);
        // A re-fire reopens `resolved` alerts (dropping the old ack) but
        // leaves `acknowledged` ones acked.
        if stored.state == AlertLifecycle::Resolved {
            stored.state = AlertLifecycle::Firing;
            stored.acked_by = None;
            stored.ack_note = None;
        }
        stored.occurrences = stored.occurrences.saturating_add(1);
        Ok(stored.view())
    }

    pub(crate) fn resolve_alert(&self, id: &str) -> anyhow::Result<Option<AlertView>> {
        let mut state = self.write()?;
        Ok(state.alerts.get_mut(id).map(|stored| {
            stored.state = AlertLifecycle::Resolved;
            stored.view()
        }))
    }

    pub(crate) fn ack_alert(
        &self,
        id: &str,
        by: &str,
        note: &str,
    ) -> anyhow::Result<Option<AlertView>> {
        let mut state = self.write()?;
        Ok(state.alerts.get_mut(id).and_then(|stored| {
            if stored.state == AlertLifecycle::Resolved {
                return None;
            }
            stored.state = AlertLifecycle::Acknowledged;
            stored.acked_by = Some(by.to_owned());
            stored.ack_note = Some(note.to_owned());
            Some(stored.view())
        }))
    }

    pub(crate) fn create_silence(&self, rule: &NewSilence) -> anyhow::Result<Silence> {
        let mut state = self.write()?;
        let now = now_ms();
        state.silences.retain(|_, rule| rule.ends_at_ms >= now);
        state.next_silence_id = state.next_silence_id.saturating_add(1);
        let silence = Silence {
            id: state.next_silence_id,
            severity: rule.severity.clone(),
            title_contains: rule.title_contains.clone(),
            alert_id: rule.alert_id.clone(),
            label_key: rule.label_key.clone(),
            label_value: rule.label_value.clone(),
            starts_at_ms: rule.starts_at_ms,
            ends_at_ms: rule.ends_at_ms,
            created_by: rule.created_by.clone(),
            comment: rule.comment.clone(),
        };
        state.silences.insert(silence.id, silence.clone());
        Ok(silence)
    }

    pub(crate) fn list_silences(&self) -> anyhow::Result<Vec<Silence>> {
        let state = self.read()?;
        let mut rules: Vec<Silence> = state.silences.values().cloned().collect();
        rules.sort_by_key(|rule| rule.ends_at_ms);
        rules.truncate(500);
        Ok(rules)
    }

    pub(crate) fn delete_silence(&self, id: i64) -> anyhow::Result<bool> {
        let mut state = self.write()?;
        Ok(state.silences.remove(&id).is_some())
    }

    pub(crate) fn list_flows(&self, filter: &FlowFilter) -> anyhow::Result<Vec<FlowRecord>> {
        let state = self.read()?;
        let limit = usize::try_from(filter.limit.clamp(1, 10_000)).unwrap_or(100);
        // Newest-first by timestamp (insertion order is NOT recency once
        // batches interleave), matching the Postgres listing exactly so
        // cursors behave the same on both backends. The stable sort keeps
        // the reversed iteration order for ties: later inserts first.
        let mut rows: Vec<FlowRecord> = state
            .flows
            .iter()
            .rev()
            .filter(|flow| {
                filter.node.as_deref().is_none_or(|node| flow.node == node)
                    && filter
                        .since_ms
                        .is_none_or(|since| flow.last_seen_unix_ms >= since)
                    && filter
                        .before_ms
                        .is_none_or(|before| flow.last_seen_unix_ms <= before)
                    && filter.namespace.as_deref().is_none_or(|namespace| {
                        flow.src_pod
                            .as_ref()
                            .is_some_and(|pod| pod.namespace == namespace)
                            || flow
                                .dst_pod
                                .as_ref()
                                .is_some_and(|pod| pod.namespace == namespace)
                    })
                    && filter.pod.as_deref().is_none_or(|pod| {
                        flow.src_pod
                            .as_ref()
                            .is_some_and(|candidate| candidate.name == pod)
                            || flow
                                .dst_pod
                                .as_ref()
                                .is_some_and(|candidate| candidate.name == pod)
                    })
            })
            .cloned()
            .collect();
        rows.sort_by_key(|row| std::cmp::Reverse(row.last_seen_unix_ms));
        rows.truncate(limit);
        Ok(rows)
    }

    pub(crate) fn list_alerts(&self, filter: &AlertFilter) -> anyhow::Result<Vec<AlertView>> {
        let wanted = filter.state.as_deref().and_then(AlertLifecycle::parse);
        let limit = usize::try_from(filter.limit.clamp(1, 10_000)).unwrap_or(100);
        let state = self.read()?;
        let mut alerts: Vec<AlertView> = state
            .alerts
            .values()
            .filter(|stored| wanted.is_none_or(|lifecycle| stored.state == lifecycle))
            .filter(|stored| {
                filter.severity.as_ref().is_none_or(|severity| {
                    super::model::severity_str(stored.alert.severity) == severity
                })
            })
            .filter(|stored| {
                filter
                    .before_ms
                    .is_none_or(|before| stored.alert.last_seen_unix_ms <= before)
            })
            .map(StoredAlert::view)
            .collect();
        alerts.sort_by_key(|view| std::cmp::Reverse(view.alert.last_seen_unix_ms));
        alerts.truncate(limit);
        Ok(alerts)
    }

    pub(crate) fn get_alert(&self, id: &str) -> anyhow::Result<Option<AlertView>> {
        let state = self.read()?;
        Ok(state.alerts.get(id).map(StoredAlert::view))
    }

    pub(crate) fn counts(&self) -> anyhow::Result<crate::metrics::StoreCounts> {
        let state = self.read()?;
        let mut counts = crate::metrics::StoreCounts {
            flows: u64::try_from(state.flows.len()).unwrap_or(u64::MAX),
            ..crate::metrics::StoreCounts::default()
        };
        for stored in state.alerts.values() {
            match stored.state {
                AlertLifecycle::Firing => {
                    counts.alerts_firing = counts.alerts_firing.saturating_add(1);
                }
                AlertLifecycle::Acknowledged => {
                    counts.alerts_acknowledged = counts.alerts_acknowledged.saturating_add(1);
                }
                AlertLifecycle::Resolved => {
                    counts.alerts_resolved = counts.alerts_resolved.saturating_add(1);
                }
            }
        }
        Ok(counts)
    }

    pub(crate) fn upsert_user(&self, email: &str, password_hash: &str) -> anyhow::Result<()> {
        let mut state = self.write()?;
        state
            .users
            .insert(email.to_owned(), password_hash.to_owned());
        Ok(())
    }

    pub(crate) fn get_password_hash(&self, email: &str) -> anyhow::Result<Option<String>> {
        let state = self.read()?;
        Ok(state.users.get(email).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{store::Store, test_helpers::*};

    #[tokio::test]
    async fn mem_flows_filter_and_order() {
        let store = Store::Memory(MemStore::default());
        store
            .save_flows(&[
                test_flow("node-1", Some(("prod", "api-0"))),
                test_flow("node-2", Some(("dev", "worker-0"))),
            ])
            .await
            .unwrap();
        let all = store
            .list_flows(&FlowFilter {
                limit: 10,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(all.len(), 2);
        // Newest first.
        assert_eq!(all[0].node, "node-2");
        let prod = store
            .list_flows(&FlowFilter {
                namespace: Some("prod".to_owned()),
                limit: 10,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(prod.len(), 1);
        assert_eq!(prod[0].node, "node-1");
        let none = store
            .list_flows(&FlowFilter {
                since_ms: Some(1_800_000_000_000),
                limit: 10,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(none, Vec::new());
        // Inclusive upper bound: boundary rows repeat, never skip.
        let page = store
            .list_flows(&FlowFilter {
                before_ms: Some(1_700_000_001_000),
                limit: 10,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(page.len(), 2);
        let empty = store
            .list_flows(&FlowFilter {
                before_ms: Some(1_700_000_000_999),
                limit: 10,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(empty, Vec::new());
    }
    #[tokio::test]
    async fn mem_alerts_merge_and_resolve() {
        let store = Store::Memory(MemStore::default());
        let first = store
            .upsert_alert(&test_alert("scan:10.0.1.4"))
            .await
            .unwrap();
        assert_eq!(first.occurrences, 1);
        assert_eq!(first.state, AlertLifecycle::Firing);
        let mut again = test_alert("scan:10.0.1.4");
        again.last_seen_unix_ms = 1_700_000_120_000;
        let second = store.upsert_alert(&again).await.unwrap();
        assert_eq!(second.occurrences, 2);
        assert_eq!(second.alert.first_seen_unix_ms, 1_700_000_000_000);
        assert_eq!(second.alert.last_seen_unix_ms, 1_700_000_120_000);
        let resolved = store.resolve_alert("scan:10.0.1.4").await.unwrap().unwrap();
        assert_eq!(resolved.state, AlertLifecycle::Resolved);
        // A re-report re-fires.
        let refired = store
            .upsert_alert(&test_alert("scan:10.0.1.4"))
            .await
            .unwrap();
        assert_eq!(refired.state, AlertLifecycle::Firing);
        assert_eq!(refired.occurrences, 3);
        assert!(store.resolve_alert("missing").await.unwrap().is_none());
    }
    #[tokio::test]
    async fn mem_alerts_keep_explanation_across_resolve_and_refire() {
        let store = Store::Memory(MemStore::default());
        let mut explained = test_alert("scan:10.0.1.4");
        explained.explanation = Some("likely backup traffic".to_owned());
        let first = store.upsert_alert(&explained).await.unwrap();
        assert_eq!(
            first.alert.explanation.as_deref(),
            Some("likely backup traffic")
        );
        // Resolving flips state only; the explanation survives.
        let resolved = store.resolve_alert(&explained.id).await.unwrap().unwrap();
        assert_eq!(resolved.state, AlertLifecycle::Resolved);
        assert_eq!(
            resolved.alert.explanation.as_deref(),
            Some("likely backup traffic")
        );
        // A re-fire without an explanation preserves the stored one ...
        let refired = store
            .upsert_alert(&test_alert("scan:10.0.1.4"))
            .await
            .unwrap();
        assert_eq!(refired.state, AlertLifecycle::Firing);
        assert_eq!(
            refired.alert.explanation.as_deref(),
            Some("likely backup traffic")
        );
        // ... while a re-fire carrying one refreshes it.
        let mut updated = test_alert("scan:10.0.1.4");
        updated.explanation = Some("confirmed exfiltration pattern".to_owned());
        let refreshed = store.upsert_alert(&updated).await.unwrap();
        assert_eq!(
            refreshed.alert.explanation.as_deref(),
            Some("confirmed exfiltration pattern")
        );
    }
    #[tokio::test]
    async fn mem_ack_survives_refire_and_clears_on_reopen() {
        let store = Store::Memory(MemStore::default());
        let fired = store
            .upsert_alert(&test_alert("scan:10.0.1.4"))
            .await
            .unwrap();
        assert_eq!(fired.state, AlertLifecycle::Firing);
        assert_eq!(fired.acked_by, None);
        let acked = store
            .ack_alert(
                &test_alert("scan:10.0.1.4").id,
                "oncall@example.com",
                "looking",
            )
            .await
            .unwrap()
            .expect("ack must apply");
        assert_eq!(acked.state, AlertLifecycle::Acknowledged);
        assert_eq!(acked.acked_by.as_deref(), Some("oncall@example.com"));
        assert_eq!(acked.ack_note.as_deref(), Some("looking"));
        // A re-fire keeps the ack.
        let refired = store
            .upsert_alert(&test_alert("scan:10.0.1.4"))
            .await
            .unwrap();
        assert_eq!(refired.state, AlertLifecycle::Acknowledged);
        assert_eq!(refired.acked_by.as_deref(), Some("oncall@example.com"));
        // Resolve, then re-fire: reopened fresh, ack dropped.
        store
            .resolve_alert(&test_alert("scan:10.0.1.4").id)
            .await
            .unwrap();
        let reopened = store
            .upsert_alert(&test_alert("scan:10.0.1.4"))
            .await
            .unwrap();
        assert_eq!(reopened.state, AlertLifecycle::Firing);
        assert_eq!(reopened.acked_by, None);
        // Acking a resolved alert is a no-op.
        store
            .resolve_alert(&test_alert("scan:10.0.1.4").id)
            .await
            .unwrap();
        assert!(
            store
                .ack_alert(&test_alert("scan:10.0.1.4").id, "x", "")
                .await
                .unwrap()
                .is_none()
        );
        assert!(store.ack_alert("missing", "x", "").await.unwrap().is_none());
    }
    #[tokio::test]
    async fn mem_silences_crud_and_prune_expired() {
        let store = Store::Memory(MemStore::default());
        let first = store
            .create_silence(&test_new_silence(u64::MAX))
            .await
            .unwrap();
        assert_eq!(first.id, 1);
        let second = store
            .create_silence(&test_new_silence(u64::MAX - 1))
            .await
            .unwrap();
        assert_eq!(second.id, 2);
        let rules = store.list_silences().await.unwrap();
        assert_eq!(rules.len(), 2);
        assert!(rules[0].ends_at_ms <= rules[1].ends_at_ms);
        assert!(store.delete_silence(first.id).await.unwrap());
        assert!(!store.delete_silence(first.id).await.unwrap());
        assert_eq!(store.list_silences().await.unwrap().len(), 1);
        // Creating a live rule prunes the expired one.
        let expired = NewSilence {
            ends_at_ms: 1,
            ..test_new_silence(u64::MAX)
        };
        let created = store.create_silence(&expired).await.unwrap();
        let _ = store
            .create_silence(&test_new_silence(u64::MAX))
            .await
            .unwrap();
        let rules = store.list_silences().await.unwrap();
        assert!(rules.iter().all(|rule| rule.id != created.id));
    }
}
