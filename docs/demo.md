# Demo (kind end-to-end)

Proves the install path and the operator → DaemonSet → API → CR loop on a
local `kind` cluster. Needs `kind`, `kubectl`, `docker`, and (for the
sensor half) a Linux node image with BTF — stock kind qualifies.

```sh
# 1. Cluster (kind auto-selects the kind-mist context on create).
kind create cluster --name mist

# 2. Build images and load them (manifests reference :dev with
#    IfNotPresent, so nothing is pulled). The eBPF object and the trunk
#    dashboard bundle are built on the host first — the Dockerfiles COPY
#    them in (same order as .github/workflows/e2e-kind.yml).
(cd crates/mist-ebpf && cargo +nightly build -Z build-std=core --release)
cp crates/mist-ebpf/target/bpfel-unknown-none/release/mist-ebpf mist-ebpf.o
(cd crates/mist-dashboard && trunk build --release)
docker build -t mist-api:dev -f docker/api.Dockerfile .
docker build -t mist-operator:dev -f docker/operator.Dockerfile .
docker build -t mist-agent:dev -f docker/agent.Dockerfile --build-arg EBPF_OBJECT=mist-ebpf.o .
kind load docker-image mist-api:dev mist-operator:dev mist-agent:dev --name mist

# 3. Install in order: RBAC+namespace, CRDs, storage, workloads, default monitor.
kubectl apply -f deploy/agent-rbac.yaml -f deploy/operator-rbac.yaml
kubectl apply -f deploy/crds/
kubectl apply -f deploy/postgres.yaml
kubectl apply -f deploy/api-deployment.yaml -f deploy/operator-deployment.yaml
kubectl apply -f deploy/samples/

# 4. Assert the control plane is up.
kubectl wait --for=condition=Established crd/trafficmonitors.mist.io --timeout=60s
kubectl wait --for=condition=Established crd/anomalyalerts.mist.io --timeout=60s
kubectl -n mist rollout status deployment/mist-operator --timeout=180s
kubectl -n mist rollout status deployment/mist-api --timeout=180s
kubectl -n mist get trafficmonitor default
# The operator renders the agent DaemonSet from the monitor:
kubectl -n mist get daemonset mist-agent

# 5. Provision auth (the API pod blocks until this Secret exists; the
#    manifests intentionally ship no credentials).
kubectl -n mist create secret generic mist-api-auth \
  --from-literal=jwt-secret="$(openssl rand -hex 32)" \
  --from-literal=admin-email=admin@example.com \
  --from-literal=admin-password='s3cret-for-kind' \
  --from-literal=ingest-token='kind-ingest-token'
kubectl -n mist rollout status deployment/mist-api --timeout=180s

# 6. Port-forward the API; log in for a token.
kubectl -n mist port-forward svc/mist-api 3000:3000 &
curl localhost:3000/healthz   # -> ok
curl localhost:3000/metrics | head -20   # public Prometheus scrape
TOKEN=$(curl -s -X POST localhost:3000/api/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"admin@example.com","password":"s3cret-for-kind"}' | \
  python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')

# 7. Synthetic traffic + spike (works without the eBPF sensor running).
#    Ingest accepts {"node": ..., "flows": [...]}; empty flows are fine for
#    plumbing. The provisioned token is required (401 without it).
curl -s -X POST localhost:3000/api/ingest \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer kind-ingest-token' \
  -d '{"node":"demo","flows":[]}' -w '\n%{http_code}\n'   # -> 202

# 8. Read back state (REST needs the token; the dashboard at
#    http://localhost:3000/ logs in through the same endpoint).
curl -s -H "authorization: Bearer $TOKEN" localhost:3000/api/flows | head -c 500; echo
curl -s -H "authorization: Bearer $TOKEN" localhost:3000/api/alerts | head -c 500; echo
kubectl -n mist get anomalyalerts

# 9. Live stream (any WS client; token travels in ?token=).
#    e.g. with websocat:  websocat "ws://localhost:3000/api/ws?token=$TOKEN"

# 10. Tear down forwarding when done.
kill %1 2>/dev/null; kind delete cluster --name mist
```

Sensor-present variant: with the images above loaded, the agent DaemonSet
attaches TC progs on the kind node (check
`kubectl -n mist logs daemonset/mist-agent` for `attached classifier`).
Generate traffic between test pods (`curl`, `iperf3`) and run an `nmap`
scan against a demo pod; within ~a minute the analyzer should fire and
both `curl -H "authorization: Bearer $TOKEN" localhost:3000/api/alerts`
and `kubectl -n mist get anomalyalerts` should show the finding (the
end-to-end validation). Alert thresholds are compiled defaults — spike ≥5x
EWMA baseline with ≥1MB, scan ≥20 distinct ports in 60s — see
`DetectorConfig::default` in `crates/mist-api/src/analyzer.rs`.
