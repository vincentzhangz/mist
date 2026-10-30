//! Prometheus text-exposition metrics for `mist-api` (no extra crates).
//!
//! Process-lifetime counters live in [`Metrics`] (atomics behind one `Arc`);
//! storage gauges come from [`StoreCounts`], queried live per scrape. The
//! `/metrics` handler renders both in Prometheus exposition format 0.0.4.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Live storage gauges for one scrape.
#[derive(Clone, Copy, Debug, Default)]
pub struct StoreCounts {
    /// Flow records currently stored.
    pub flows: u64,
    /// Alerts in `firing` state.
    pub alerts_firing: u64,
    /// Alerts in `resolved` state.
    pub alerts_resolved: u64,
}

/// Process-lifetime counters. Cheap to clone (`Arc`); all atomics relaxed —
/// scrape-time races of a single increment are acceptable for monitoring.
#[derive(Debug)]
pub struct Metrics {
    /// Batches accepted into the analyzer channel.
    ingest_batches_accepted: AtomicU64,
    /// Flow records accepted into the analyzer channel.
    ingest_flows_accepted: AtomicU64,
    /// Batches shed because the analyzer channel was saturated.
    ingest_batches_shed: AtomicU64,
    /// Flow records persisted by the analyzer.
    flows_persisted: AtomicU64,
    /// Batches whose persistence failed.
    persistence_failures: AtomicU64,
    /// Alerts fired (upserted as `firing`).
    alerts_fired: AtomicU64,
    /// Failed `AnomalyAlert` mirror webhook calls.
    webhook_failures: AtomicU64,
    /// Login attempts rejected by the rate limiter.
    logins_limited: AtomicU64,
    started_at: Instant,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            ingest_batches_accepted: AtomicU64::new(0),
            ingest_flows_accepted: AtomicU64::new(0),
            ingest_batches_shed: AtomicU64::new(0),
            flows_persisted: AtomicU64::new(0),
            persistence_failures: AtomicU64::new(0),
            alerts_fired: AtomicU64::new(0),
            webhook_failures: AtomicU64::new(0),
            logins_limited: AtomicU64::new(0),
            started_at: Instant::now(),
        }
    }
}

impl Metrics {
    /// Record one batch accepted by `/api/ingest` with `flows` records.
    pub fn batch_accepted(&self, flows: usize) {
        self.ingest_batches_accepted.fetch_add(1, Ordering::Relaxed);
        self.ingest_flows_accepted
            .fetch_add(u64::try_from(flows).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    /// Record one batch shed because the analyzer channel was saturated.
    pub fn batch_shed(&self) {
        self.ingest_batches_shed.fetch_add(1, Ordering::Relaxed);
    }

    /// Record one batch persisted by the analyzer with `flows` records.
    pub fn batch_persisted(&self, flows: usize) {
        self.flows_persisted
            .fetch_add(u64::try_from(flows).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    /// Record one batch whose persistence failed.
    pub fn persistence_failed(&self) {
        self.persistence_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Record one alert fired.
    pub fn alert_fired(&self) {
        self.alerts_fired.fetch_add(1, Ordering::Relaxed);
    }

    /// Record one failed operator webhook call.
    pub fn webhook_failed(&self) {
        self.webhook_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Record one login attempt rejected by the rate limiter.
    pub fn login_limited(&self) {
        self.logins_limited.fetch_add(1, Ordering::Relaxed);
    }

    fn load(counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }

    fn emit(out: &mut String, name: &str, help: &str, kind: &str, value: u64) {
        out.push_str("# HELP ");
        out.push_str(name);
        out.push(' ');
        out.push_str(help);
        out.push_str("\n# TYPE ");
        out.push_str(name);
        out.push(' ');
        out.push_str(kind);
        out.push('\n');
        out.push_str(name);
        out.push(' ');
        out.push_str(&value.to_string());
        out.push('\n');
    }

    fn emit_counter(out: &mut String, name: &str, help: &str, value: u64) {
        Self::emit(out, name, help, "counter", value);
    }

    fn emit_gauge(out: &mut String, name: &str, help: &str, value: u64) {
        Self::emit(out, name, help, "gauge", value);
    }

    /// Render process counters plus `store` gauges in exposition format.
    #[must_use]
    pub fn render(&self, store: &StoreCounts) -> String {
        let mut out = String::new();
        Self::emit_counter(
            &mut out,
            "mist_api_ingest_batches_accepted_total",
            "Flow batches accepted into the analyzer channel.",
            Self::load(&self.ingest_batches_accepted),
        );
        Self::emit_counter(
            &mut out,
            "mist_api_ingest_flows_accepted_total",
            "Flow records accepted into the analyzer channel.",
            Self::load(&self.ingest_flows_accepted),
        );
        Self::emit_counter(
            &mut out,
            "mist_api_ingest_batches_shed_total",
            "Flow batches shed while the analyzer channel was saturated.",
            Self::load(&self.ingest_batches_shed),
        );
        Self::emit_counter(
            &mut out,
            "mist_api_flows_persisted_total",
            "Flow records persisted by the analyzer.",
            Self::load(&self.flows_persisted),
        );
        Self::emit_counter(
            &mut out,
            "mist_api_persistence_failures_total",
            "Batches whose flow persistence failed.",
            Self::load(&self.persistence_failures),
        );
        Self::emit_counter(
            &mut out,
            "mist_api_alerts_fired_total",
            "Alerts fired by the analyzer.",
            Self::load(&self.alerts_fired),
        );
        Self::emit_counter(
            &mut out,
            "mist_api_webhook_failures_total",
            "Failed AnomalyAlert mirror webhook calls.",
            Self::load(&self.webhook_failures),
        );
        Self::emit_counter(
            &mut out,
            "mist_api_logins_limited_total",
            "Login attempts rejected by the rate limiter.",
            Self::load(&self.logins_limited),
        );
        Self::emit_gauge(
            &mut out,
            "mist_api_flows_stored",
            "Flow records currently in storage.",
            store.flows,
        );
        Self::emit_gauge(
            &mut out,
            "mist_api_alerts_firing",
            "Alerts currently firing.",
            store.alerts_firing,
        );
        Self::emit_gauge(
            &mut out,
            "mist_api_alerts_resolved",
            "Alerts currently resolved.",
            store.alerts_resolved,
        );
        Self::emit_gauge(
            &mut out,
            "mist_api_uptime_seconds",
            "Seconds since process start.",
            self.started_at.elapsed().as_secs(),
        );
        out.push_str("# HELP mist_api_build_info Build metadata.\n");
        out.push_str("# TYPE mist_api_build_info gauge\n");
        out.push_str("mist_api_build_info{version=\"");
        out.push_str(env!("CARGO_PKG_VERSION"));
        out.push_str("\"} 1\n");
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_exposes_counters_and_gauges() {
        let metrics = Metrics::default();
        metrics.batch_accepted(7);
        metrics.batch_accepted(3);
        metrics.batch_shed();
        metrics.batch_persisted(9);
        metrics.persistence_failed();
        metrics.alert_fired();
        metrics.webhook_failed();
        metrics.login_limited();
        let store = StoreCounts {
            flows: 42,
            alerts_firing: 2,
            alerts_resolved: 5,
        };
        let body = metrics.render(&store);
        for line in [
            "# HELP mist_api_ingest_batches_accepted_total ",
            "# TYPE mist_api_ingest_batches_accepted_total counter",
            "mist_api_ingest_batches_accepted_total 2",
            "mist_api_ingest_flows_accepted_total 10",
            "mist_api_ingest_batches_shed_total 1",
            "mist_api_flows_persisted_total 9",
            "mist_api_persistence_failures_total 1",
            "mist_api_alerts_fired_total 1",
            "mist_api_webhook_failures_total 1",
            "mist_api_logins_limited_total 1",
            "# TYPE mist_api_flows_stored gauge",
            "mist_api_flows_stored 42",
            "mist_api_alerts_firing 2",
            "mist_api_alerts_resolved 5",
            "mist_api_uptime_seconds ",
            "mist_api_build_info{version=\"",
        ] {
            assert!(body.contains(line), "missing {line:?} in:\n{body}");
        }
        assert!(body.ends_with('\n'));
    }
}
