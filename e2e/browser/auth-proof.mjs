// Auth proof: exercises the API auth surface against kind.
// login -> JWT flows -> ingest 401/202 -> ack/silence lifecycle -> agents shipping (metrics).
import { NS, EMAIL, PASSWORD, INGEST_TOKEN, baseFor, check, failureCount, run, startPortForward } from './lib.mjs';

const PORT = process.env.MIST_PORT ?? '3103';
const BASE = baseFor(PORT);

async function main() {
  const pf = await startPortForward(NS, PORT, BASE);
  try {
    const batch = { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"node":"probe","flows":[]}' };
    const noTok = await fetch(`${BASE}/api/ingest`, batch);
    check('ingest without token is 401', noTok.status === 401, `status=${noTok.status}`);
    const badTok = await fetch(`${BASE}/api/ingest`, {
      ...batch, headers: { ...batch.headers, authorization: 'Bearer wrong' },
    });
    check('ingest with wrong token is 401', badTok.status === 401, `status=${badTok.status}`);
    const okTok = await fetch(`${BASE}/api/ingest`, {
      ...batch, headers: { ...batch.headers, authorization: `Bearer ${INGEST_TOKEN}` },
    });
    check('ingest with token is 202', okTok.status === 202, `status=${okTok.status}`);
    const loginRes = await fetch(`${BASE}/api/auth/login`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: EMAIL, password: PASSWORD }),
    });
    const login = await loginRes.json();
    check('login via seeded admin', loginRes.status === 200 && !!login.token, `status=${loginRes.status}`);
    const flowsRes = await fetch(`${BASE}/api/flows?limit=3`, {
      headers: { authorization: `Bearer ${login.token}` },
    });
    const flows = await flowsRes.json();
    check('flows readable with JWT', Array.isArray(flows.flows) && flows.flows.length > 0, `rows=${flows.flows.length}`);
    const limitedRes = await fetch(`${BASE}/api/flows?limit=100`, {
      headers: { authorization: `Bearer ${login.token}` },
    });
    const limited = await limitedRes.json();
    check('limit param honored', Array.isArray(limited.flows) && limited.flows.length <= 100, `rows=${limited.flows.length}`);
    const page1 = await (await fetch(`${BASE}/api/flows?limit=2`, {
      headers: { authorization: `Bearer ${login.token}` },
    })).json();
    const cursor = page1.next_cursor;
    check('flows page carries cursor', page1.flows.length === 2 && typeof cursor === 'number', `cursor=${cursor}`);
    const page2 = await (await fetch(`${BASE}/api/flows?limit=2&before_ms=${cursor}`, {
      headers: { authorization: `Bearer ${login.token}` },
    })).json();
    check('flows cursor pages older', page2.flows.length > 0 && page2.flows.every((f) => f.last_seen_unix_ms <= cursor), `rows=${page2.flows.length}`);
    const authz = { authorization: `Bearer ${login.token}` };
    // Fire a deterministic alert via a fresh TEST-NET endpoint (unique port per run).
    const port = 5000 + (Date.now() % 1000);
    const now = Date.now();
    await fetch(`${BASE}/api/ingest`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${INGEST_TOKEN}` },
      body: JSON.stringify({ node: 'probe', flows: [{
        key: { src_ip: '10.0.0.5', src_port: 54321, dst_ip: '203.0.113.7', dst_port: port, protocol: 6 },
        direction: 'egress', bytes: 128, packets: 2,
        start_unix_ms: now, last_seen_unix_ms: now, node: 'probe',
        src_pod: { namespace: 'default', name: 'web-0', labels: { app: 'web' } }, dst_pod: null,
      }, {
        key: { src_ip: '10.0.0.5', src_port: 54322, dst_ip: '10.96.0.10', dst_port: 53, protocol: 17 },
        direction: 'egress', bytes: 64, packets: 1,
        start_unix_ms: now, last_seen_unix_ms: now, node: 'probe',
        src_pod: { namespace: 'default', name: 'web-0', labels: { app: 'web' } },
        dst_pod: { namespace: 'kube-system', name: 'kube-dns-xyz', labels: { 'k8s-app': 'kube-dns' } },
      }] }),
    });
    const alertId = `new-endpoint:default/web-0:203.0.113.7:${port}`;
    let seen = null;
    for (let i = 0; i < 40 && !seen; i++) {
      await new Promise((r) => setTimeout(r, 500));
      const list = await (await fetch(`${BASE}/api/alerts?limit=100`, { headers: authz })).json();
      seen = list.alerts.find((a) => a.id === alertId);
    }
    check('ingest fires new-endpoint alert', !!seen, alertId);
    const apage1 = await (await fetch(`${BASE}/api/alerts?limit=1`, { headers: authz })).json();
    const acursor = apage1.next_cursor;
    check('alerts page carries cursor', apage1.alerts.length === 1 && typeof acursor === 'number', `cursor=${acursor}`);
    const apage2 = await (await fetch(`${BASE}/api/alerts?limit=1&before_ms=${acursor}`, { headers: authz })).json();
    check('alerts cursor pages older', apage2.alerts.length > 0 && apage2.alerts.every((a) => a.last_seen_unix_ms <= acursor), `rows=${apage2.alerts.length}`);
    const enc = encodeURIComponent(alertId);
    const acked = await (await fetch(`${BASE}/api/alerts/${enc}/ack`, {
      method: 'POST', headers: { ...authz, 'content-type': 'application/json' },
      body: JSON.stringify({ note: 'proof-ack' }),
    })).json();
    check('ack marks alert acknowledged', acked.state === 'acknowledged' && acked.acked_by === EMAIL, acked.state);
    const badSev = await fetch(`${BASE}/api/silences`, {
      method: 'POST', headers: { ...authz, 'content-type': 'application/json' },
      body: JSON.stringify({ severity: 'bogus', ends_at_ms: Date.now() + 60000 }),
    });
    const badWindow = await fetch(`${BASE}/api/silences`, {
      method: 'POST', headers: { ...authz, 'content-type': 'application/json' },
      body: JSON.stringify({ starts_at_ms: 2000, ends_at_ms: 1000 }),
    });
    check('silence validation rejects bad input', badSev.status === 400 && badWindow.status === 400);
    const rule = await (await fetch(`${BASE}/api/silences`, {
      method: 'POST', headers: { ...authz, 'content-type': 'application/json' },
      body: JSON.stringify({ alert_id: alertId, ends_at_ms: Date.now() + 60000, comment: 'proof' }),
    })).json();
    const muted = await (await fetch(`${BASE}/api/alerts/${enc}`, { headers: authz })).json();
    check('silence mutes alert', muted.silenced === true, `rule=${rule.id}`);
    const unmuted = await fetch(`${BASE}/api/silences/${rule.id}`, { method: 'DELETE', headers: authz });
    const clear = await (await fetch(`${BASE}/api/alerts/${enc}`, { headers: authz })).json();
    check('unmute clears flag', unmuted.status === 204 && clear.silenced === false);
    const done = await (await fetch(`${BASE}/api/alerts/${enc}/resolve`, { method: 'POST', headers: authz })).json();
    check('resolve after ack works', done.state === 'resolved');
    const noNs = await fetch(`${BASE}/api/policies/recommend`, { headers: authz });
    check('recommend without namespace is 400', noNs.status === 400, `status=${noNs.status}`);
    const rec = await (await fetch(`${BASE}/api/policies/recommend?namespace=default`, { headers: authz })).json();
    check('recommend returns policy YAML', typeof rec.yaml === 'string' && rec.yaml.includes('kind: NetworkPolicy'), `flows=${rec.flows_analyzed}`);
    // The labeled synthetic flows above must surface as a workload policy
    // with a DNS carve-out (poll: analyzer persistence races this read, and
    // older runs may have left DNS-less rows behind).
    let wpol = null;
    for (let i = 0; i < 40 && !(wpol?.dns_egress?.length > 0); i++) {
      await new Promise((r) => setTimeout(r, 500));
      const r = await (await fetch(`${BASE}/api/policies/recommend?namespace=default`, { headers: authz })).json();
      wpol = r.workload_policies?.find((w) => w.workload === 'web-observed');
    }
    check('recommend groups labeled pods by workload', !!wpol && wpol.selector?.app === 'web', `selector=${JSON.stringify(wpol?.selector)}`);
    const dns0 = wpol?.dns_egress?.[0];
    check('recommend carves out DNS per workload', !!dns0 && dns0.namespace === 'kube-system' && dns0.pod_selector?.['k8s-app'] === 'kube-dns', `dns=${JSON.stringify(dns0)}`);
    const metrics = await (await fetch(`${BASE}/metrics`)).text();
    const accepted = metrics.match(/mist_api_ingest_batches_accepted_total (\d+)/)?.[1];
    check('agents shipping through token auth', Number(accepted) > 0, `accepted=${accepted}`);
    const ov = await (await fetch(`${BASE}/api/health/overview`, { headers: authz })).json();
    check('health overview reports agents', Array.isArray(ov.agents) && ov.agents.length > 0 && typeof ov.uptime_secs === 'number', `agents=${ov.agents?.length}`);
    check('health overview reports queue', typeof ov.analyzer_queue?.depth === 'number' && typeof ov.analyzer_queue?.capacity === 'number', `queue=${ov.analyzer_queue?.depth}/${ov.analyzer_queue?.capacity}`);
  } finally {
    pf.kill('SIGTERM');
  }
  process.exit(failureCount() ? 1 : 0);
}

run(main);
