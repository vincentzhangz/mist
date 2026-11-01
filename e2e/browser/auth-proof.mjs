// Auth proof: exercises the API auth surface against kind.
// login -> JWT flows -> ingest 401/202 -> ack/silence lifecycle -> agents shipping (metrics).
import { spawn } from 'node:child_process';

const NS = process.env.MIST_NAMESPACE ?? 'mist';
const PORT = process.env.MIST_PORT ?? '3103';
const BASE = `http://127.0.0.1:${PORT}`;
const EMAIL = process.env.MIST_EMAIL ?? 'admin@example.com';
const PASSWORD = process.env.MIST_PASSWORD ?? 's3cret-for-kind';
const INGEST_TOKEN = process.env.MIST_INGEST_TOKEN ?? 'kind-ingest-token';

let failures = 0;
const check = (name, ok, extra = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${extra ? ' — ' + extra : ''}`);
  if (!ok) failures++;
};

async function main() {
  const pf = spawn('kubectl', ['-n', NS, 'port-forward', 'svc/mist-api', `${PORT}:3000`], { stdio: 'ignore' });
  try {
    for (let i = 0; i < 150; i++) {
      try {
        const r = await fetch(`${BASE}/healthz`);
        if (r.status === 200) break;
      } catch { /* not up */ }
      await new Promise((r) => setTimeout(r, 200));
    }
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
    check('flows readable with JWT', Array.isArray(flows) && flows.length > 0, `rows=${flows.length}`);
    const limitedRes = await fetch(`${BASE}/api/flows?limit=100`, {
      headers: { authorization: `Bearer ${login.token}` },
    });
    const limited = await limitedRes.json();
    check('limit param honored', Array.isArray(limited) && limited.length <= 100, `rows=${limited.length}`);
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
        src_pod: { namespace: 'default', name: 'web-0' }, dst_pod: null,
      }] }),
    });
    const alertId = `new-endpoint:default/web-0:203.0.113.7:${port}`;
    let seen = null;
    for (let i = 0; i < 40 && !seen; i++) {
      await new Promise((r) => setTimeout(r, 500));
      const list = await (await fetch(`${BASE}/api/alerts?limit=100`, { headers: authz })).json();
      seen = list.find((a) => a.id === alertId);
    }
    check('ingest fires new-endpoint alert', !!seen, alertId);
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
    const metrics = await (await fetch(`${BASE}/metrics`)).text();
    const accepted = metrics.match(/mist_api_ingest_batches_accepted_total (\d+)/)?.[1];
    check('agents shipping through token auth', Number(accepted) > 0, `accepted=${accepted}`);
  } finally {
    pf.kill('SIGTERM');
  }
  process.exit(failures ? 1 : 0);
}

main().catch((e) => { console.error('FATAL', e); process.exit(2); });
