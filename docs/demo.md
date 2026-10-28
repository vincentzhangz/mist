# Demo (kind end-to-end)

Proves the install path and the operator → DaemonSet → API → CR loop on a
local `kind` cluster. Needs `kind`, `kubectl`, and (for the sensor half) a
Linux node image with BTF — stock kind qualifies.

```sh
# 1. Cluster (kind auto-selects the kind-mist context on create).
kind create cluster --name mist

# 2. Install in order: RBAC+namespace, CRDs, storage, workloads, default monitor.
kubectl apply -f deploy/agent-rbac.yaml -f deploy/operator-rbac.yaml
kubectl apply -f deploy/crds/
kubectl apply -f deploy/postgres.yaml
kubectl apply -f deploy/api-deployment.yaml -f deploy/operator-deployment.yaml
kubectl apply -f deploy/samples/

# 3. Assert the control plane is up.
kubectl wait --for=condition=Established crd/trafficmonitors.mist.io --timeout=60s
kubectl wait --for=condition=Established crd/anomalyalerts.mist.io --timeout=60s
kubectl -n mist rollout status deployment/mist-operator --timeout=180s
kubectl -n mist rollout status deployment/mist-api --timeout=180s
kubectl -n mist get trafficmonitor default
# The operator renders the agent DaemonSet from the monitor:
kubectl -n mist get daemonset mist-agent

# 4. Port-forward the API (no login — see docs/auth.md).
kubectl -n mist port-forward svc/mist-api 3000:3000 &
curl localhost:3000/healthz   # -> ok

# 5. Synthetic traffic + spike (works without the eBPF sensor running).
#    Ingest accepts {"node": ..., "flows": [...]}; empty flows are fine for plumbing.
curl -s -X POST localhost:3000/api/ingest \
  -H 'content-type: application/json' \
  -d '{"node":"demo","flows":[]}' -w '\n%{http_code}\n'   # -> 202

# 6. Read back state.
curl -s localhost:3000/api/flows | head -c 500; echo
curl -s localhost:3000/api/alerts | head -c 500; echo
kubectl -n mist get anomalyalerts

# 7. Live stream (any WS client; no token required today).
#    e.g. with websocat:  websocat ws://localhost:3000/api/ws

# 8. Tear down forwarding when done.
kill %1 2>/dev/null; kind delete cluster --name mist
```

Sensor-present variant: with agent images built and pushed (`:dev` tags
replaced), generate traffic between test pods (`curl`, `iperf3`) and run an
`nmap` scan against a demo pod; within ~a minute the analyzer should fire
and both `curl localhost:3000/api/alerts` and
`kubectl -n mist get anomalyalerts` should show the finding (the
end-to-end validation). Alert thresholds are compiled defaults — spike ≥5x
EWMA baseline with ≥1MB, scan ≥20 distinct ports in 60s — see
`DetectorConfig::default` in `crates/mist-api/src/analyzer.rs`.
