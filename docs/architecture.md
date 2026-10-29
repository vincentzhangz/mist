# Architecture

mist is a Kubernetes operator that captures per-node network flows with
eBPF, scores them for anomalies, and surfaces findings on a dashboard and
as `AnomalyAlert` custom resources.

## Data flow

```
[node] TC ingress/egress eBPF progs (aya, mist-ebpf)
  → per-CPU flow-count maps ──poll──▶ mist-agent (DaemonSet, per node)
  → pod-IP enrichment via k8s API ──POST /api/ingest──▶ mist-api (Axum)
  → analyzer module scores vs baselines ──▶ Postgres + WebSocket broadcast
  → mist-dashboard (Leptos CSR/WASM) + AnomalyAlert CRs (via operator webhook)
```

1. **Sensor** (`crates/mist-ebpf` + `mist-agent`). TC classifiers
   (`mist_ingress`, `mist_egress`) attached to every up, non-loopback
   interface aggregate 5-tuple flow counters (bytes, packets, timestamps,
   TCP flags) in per-CPU `FLOWS` maps plus a `STATS` array
   (updated/skipped/map-full). The agent drains the maps every
   `--interval-secs` (default 5s), attributes endpoints to pods via the
   Kubernetes API (30s pod cache), and POSTs a `FlowBatch` to
   `{api-url}/api/ingest`. Drain is snapshot-then-remove: a packet counted
   between read and remove is lost (small undercount) so the map stays
   bounded without kernel-side LRU.
2. **API + analyzer** (`crates/mist-api`). Ingest lands on a bounded
   channel (capacity 64; saturated → `503`, batch shed). A dedicated Tokio
   task (`analyzer::run_analyzer`) scores batches; HTTP handlers never score
   inline. Storage is Postgres when `DATABASE_URL` is set, otherwise
   in-memory. REST serves history; a broadcast channel (capacity 256;
   lagged WS receivers skip, never stall) feeds `GET /api/ws`.
   Alert explanations are a stub seam, not an LLM call: `run_analyzer`
   passes every fired alert through an `analyzer::Explainer`
   (`NoopExplainer` today, returning `None`) before upsert, and tags the
   alert `explainer=<name>` (`none`). The store keeps a stored explanation
   when a re-fire carries none and refreshes it when one arrives, so
   resolve/re-fire never wipes it; the webhook and dashboard already carry
   the optional field. A future LLM implementation only implements the
   trait and wires it into `run_analyzer` in `main` — no new env vars,
   no detector/store/webhook changes. Wiring (channels, storage, webhook,
   config, metrics) travels as one `analyzer::AnalyzerDeps` struct.
   Observability is a public `GET /metrics` (Prometheus exposition, no
   extra crates): ingest/persist/fire counters plus live storage gauges
   (`mist_api_flows_stored`, `mist_api_alerts_{firing,resolved}`).
3. **Operator** (`crates/mist-operator`). Watches `TrafficMonitor` in
   `OPERATOR_NAMESPACE` (default `mist`); renders the `mist-agent`
   DaemonSet from the **oldest** instance (extras marked `Superseded`);
   deleting all monitors deletes the DaemonSet (finalizer-free; 404 on
   delete is ignored). The alert webhook (`POST /alerts` on
   `--webhook-addr`, default `0.0.0.0:8081`) mirrors analyzer findings as
   `AnomalyAlert` CRs, deduplicated by alert id, with status
   (first/last-seen, occurrences) written via a dedicated status patch.
4. **Dashboard** (`crates/mist-dashboard`). Leptos 0.8 CSR app with
   real views: `/login` (email+password), `/` (flows table with live WS
   prepend), `/alerts` (filterable list + detail + resolve), behind an
   auth-guarded shell with header nav, WS status dot, and logout. The API
   serves the trunk bundle from `SERVE_DIR` (default
   `crates/mist-dashboard/dist`, baked at `/srv/dashboard` in the image)
   with `index.html` fallback for client routes; unknown `/api/*` paths
   stay JSON 404s.

## eBPF TC design

- **TC, not XDP**: TC ingress+egress sees pod traffic on node/veth
  interfaces in both directions regardless of NIC driver; XDP is
  ingress-only and driver-dependent (rejected for v1; possible fast path).
- **Flow metadata only**: 5-tuple key, counters, timestamps, TCP flags.
  No payloads leave the kernel (bounds overhead, sidesteps payload privacy).
- **Drain semantics**: per-CPU aggregation in userspace (`aggregate` sums
  packets/bytes, min start, max last-seen, ORs flags); timestamps map boot
  nanoseconds → unix millis via the `/proc/uptime` anchor; unknown direction
  encodings fall back to ingress.
- **Panic-freedom rule** (`crates/mist-ebpf/Cargo.toml`): eBPF programs
  cannot unwind — any panic path becomes a trap stub that can break program
  loading. So `debug-assertions = false` (real bugs surface as verifier
  rejections or wrong test behavior, not trap stubs) while
  `overflow-checks = true` (accidental wrapping fails loudly at load time;
  intentional wrapping uses explicit `wrapping_*`).
- **Privileges**: the agent needs `hostNetwork`, `privileged`
  (`CAP_BPF`/`CAP_NET_ADMIN` semantics), `/sys` mounted read-only, and
  `get/list/watch pods` + `get/list nodes` RBAC.

## CRDs

- `TrafficMonitor` (`trafficmonitors.mist.io`): `watchedNamespaces` (empty
  = all; recorded for the agent, filtering lands with the analyzer),
  `sampleIntervalSecs` (default 5), `agentImage` (default
  `mist-agent:dev`), `nodeSelector`, `apiUrl` (default
  `http://mist-api.mist.svc.cluster.local:3000`), `objectPath` (default
  `/etc/mist/mist-ebpf.o`), `apiTokenSecretName` (optional; the Secret's
  `ingest-token` key becomes the agent's `MIST_API_TOKEN`). Status:
  `Pending`/`Ready`/`Superseded`.
- `AnomalyAlert` (`anomalyalerts.mist.io`): `alertId`, `severity`
  (`info`/`warning`/`critical`), `title`, `detail`, optional `explanation`,
  `workloadNamespace`/`workloadName`, `attributes`. Status: `state`
  (`Firing`/`Resolved`), window millis, `occurrences`. CR names are
  DNS-safe slugs of the alert id (lowercased, dashes, ≤200 chars); labels
  carry `mist.io/severity|namespace|pod`.
