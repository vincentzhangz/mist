// Shared harness for the browser proofs: env, check helper, port-forward.
import { spawn } from 'node:child_process';

export const NS = process.env.MIST_NAMESPACE ?? 'mist';
export const EMAIL = process.env.MIST_EMAIL ?? 'admin@example.com';
export const PASSWORD = process.env.MIST_PASSWORD ?? 's3cret-for-kind';
export const INGEST_TOKEN = process.env.MIST_INGEST_TOKEN ?? 'kind-ingest-token';

export const baseFor = (port) => `http://127.0.0.1:${port}`;

let failures = 0;

export const check = (name, ok, extra = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${extra ? ' — ' + extra : ''}`);
  if (!ok) failures++;
};

export const failureCount = () => failures;

/// Spawn a port-forward and wait for /healthz; the caller kills it in `finally`.
export async function startPortForward(ns, port, base) {
  const pf = spawn('kubectl', ['-n', ns, 'port-forward', 'svc/mist-api', `${port}:3000`], { stdio: 'ignore' });
  for (let i = 0; i < 150; i++) {
    try {
      const r = await fetch(`${base}/healthz`);
      if (r.status === 200) break;
    } catch { /* not up */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  return pf;
}

export function run(main) {
  main().catch((e) => { console.error('FATAL', e); process.exit(2); });
}
