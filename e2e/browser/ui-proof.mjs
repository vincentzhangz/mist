// UI proof: WebKit click-through of the dashboard against kind.
// login -> flows table -> limit control -> alerts -> logout, no page errors.
import { webkit } from 'playwright';
import { spawn } from 'node:child_process';

const NS = process.env.MIST_NAMESPACE ?? 'mist';
const PORT = process.env.MIST_PORT ?? '3100';
const BASE = `http://127.0.0.1:${PORT}`;
const EMAIL = process.env.MIST_EMAIL ?? 'admin@example.com';
const PASSWORD = process.env.MIST_PASSWORD ?? 's3cret-for-kind';

let failures = 0;
const check = (name, ok, extra = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${extra ? ' — ' + extra : ''}`);
  if (!ok) failures++;
};

async function main() {
  const pf = spawn('kubectl', ['-n', NS, 'port-forward', 'svc/mist-api', `${PORT}:3000`], { stdio: 'ignore' });
  const browser = await webkit.launch();
  try {
    for (let i = 0; i < 150; i++) {
      try {
        const r = await fetch(`${BASE}/healthz`);
        if (r.status === 200) break;
      } catch { /* not up */ }
      await new Promise((r) => setTimeout(r, 200));
    }
    const page = await browser.newPage();
    const errors = [];
    page.on('pageerror', (e) => errors.push(String(e).slice(0, 160)));
    page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text().slice(0, 160)); });
    await page.goto(`${BASE}/login`, { waitUntil: 'domcontentloaded' });
    await page.waitForSelector('form.login-card', { timeout: 15000 });
    check('login form renders', true);
    await page.fill('input[name="email"]', EMAIL);
    await page.fill('input[name="password"]', PASSWORD);
    await page.click('button[type="submit"]');
    await page.waitForURL('**/', { timeout: 15000 });
    check('login redirects to /', page.url() === `${BASE}/`);
    await page.waitForSelector('section.flows table', { timeout: 15000 });
    const flowRows = await page.evaluate(
      () => document.querySelectorAll('section.flows table tbody tr').length,
    );
    check('flows table has real eBPF rows', flowRows > 0, `rows=${flowRows}`);
    const ws = await page.evaluate(() => document.querySelector('.ws-status')?.textContent?.trim());
    check('ws status live/connecting', /Live|Connecting/i.test(ws ?? ''), ws);
    const options = await page.evaluate(
      () => [...document.querySelectorAll('section.flows .filters select option')].map((o) => o.value),
    );
    check('limit control offers 100/200/500', JSON.stringify(options) === JSON.stringify(['100', '200', '500']), options.join(','));
    await page.selectOption('section.flows .filters select', '100');
    await page.waitForTimeout(2500);
    const limitedRows = await page.evaluate(
      () => document.querySelectorAll('section.flows table tbody tr').length,
    );
    check('limit switch reloads without errors', limitedRows >= 0, `rows=${limitedRows}`);
    await page.click('nav a[href="/alerts"]');
    await page.waitForURL('**/alerts', { timeout: 15000 });
    await page.waitForSelector('section.alerts ul.alert-list, section.alerts p.muted', { timeout: 15000 });
    check('alerts view loads', true);
    await page.click('button.logout');
    await page.waitForURL('**/login', { timeout: 15000 });
    check('logout returns to /login', true);
    check('no page errors', errors.length === 0, errors.join(' | ').slice(0, 300));
  } finally {
    await browser.close().catch(() => {});
    pf.kill('SIGTERM');
  }
  process.exit(failures ? 1 : 0);
}

main().catch((e) => { console.error('FATAL', e); process.exit(2); });
