// Auth proof: exercises the API auth surface against kind.
// login -> JWT flows -> ingest 401/202 -> agents shipping (metrics).
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
    const metrics = await (await fetch(`${BASE}/metrics`)).text();
    const accepted = metrics.match(/mist_api_ingest_batches_accepted_total (\d+)/)?.[1];
    check('agents shipping through token auth', Number(accepted) > 0, `accepted=${accepted}`);
  } finally {
    pf.kill('SIGTERM');
  }
  process.exit(failures ? 1 : 0);
}

main().catch((e) => { console.error('FATAL', e); process.exit(2); });
