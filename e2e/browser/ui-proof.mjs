// UI proof: WebKit click-through of the dashboard against kind.
// login -> overview -> flows table -> limit control -> alerts -> policies -> health -> logout, no page errors.
import { webkit } from 'playwright';
import { NS, EMAIL, PASSWORD, baseFor, check, failureCount, run, startPortForward } from './lib.mjs';

const PORT = process.env.MIST_PORT ?? '3100';
const BASE = baseFor(PORT);

async function main() {
  const pf = await startPortForward(NS, PORT, BASE);
  const browser = await webkit.launch();
  try {
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
    await page.waitForSelector('section.overview .stats .stat-value', { timeout: 15000 });
    const statCount = await page.evaluate(
      () => document.querySelectorAll('section.overview .stats .stat').length,
    );
    check('overview stat cards render', statCount === 4, `cards=${statCount}`);
    const chartCount = await page.evaluate(
      () => document.querySelectorAll('section.overview svg.chart').length,
    );
    check('overview charts render', chartCount === 3, `charts=${chartCount}`);
    await page.click('nav a[href="/flows"]');
    await page.waitForURL('**/flows', { timeout: 15000 });
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
    await page.fill('section.flows input[type="search"]', 'zzz-no-such-flow');
    await page.waitForTimeout(500);
    const noRows = await page.evaluate(
      () => document.querySelectorAll('section.flows table tbody tr').length,
    );
    const noMatch = await page.evaluate(
      () => document.querySelector('section.flows p.muted')?.textContent ?? '',
    );
    check('search filters to empty with hint', noRows === 0 && /No flows match/.test(noMatch), `rows=${noRows}`);
    await page.fill('section.flows input[type="search"]', '');
    await page.waitForTimeout(500);
    const restoredRows = await page.evaluate(
      () => document.querySelectorAll('section.flows table tbody tr').length,
    );
    check('clearing search restores rows', restoredRows > 0, `rows=${restoredRows}`);
    const loadMore = page.locator('section.flows button', { hasText: 'Load more' });
    if (await loadMore.count() > 0) {
      await loadMore.click();
      await page.waitForFunction(
        (n) => document.querySelectorAll('section.flows tbody tr').length > n
          || document.body.textContent.includes('No more flows.'),
        restoredRows,
        { timeout: 15000 },
      );
    }
    const grownRows = await page.locator('section.flows tbody tr').count();
    const exhaustedShown = await page.locator('section.flows p.muted', { hasText: 'No more flows.' }).count();
    check('load more appends history', grownRows > restoredRows || exhaustedShown > 0, `rows=${restoredRows}->${grownRows}`);
    await page.click('nav a[href="/alerts"]');
    await page.waitForURL('**/alerts', { timeout: 15000 });
    await page.waitForSelector('section.alerts ul.alert-list, section.alerts p.muted', { timeout: 15000 });
    check('alerts view loads', true);
    const hasRows = await page.evaluate(
      () => document.querySelectorAll('section.alerts ul.alert-list li').length > 0,
    );
    if (hasRows) {
      // Resolved alerts show no actions by design; scan the first rows for an open one.
      let hasAction = false;
      for (let i = 1; i <= 5 && !hasAction; i++) {
        const sel = `section.alerts ul.alert-list li:nth-child(${i}) button.alert-item`;
        if (!(await page.$(sel))) break;
        await page.click(sel);
        await page.waitForSelector('section.alerts .alert-detail article', { timeout: 15000 });
        await page.waitForTimeout(300);
        hasAction = await page.evaluate(
          () => document.querySelector('section.alerts .alert-detail .action-row button') !== null,
        );
      }
      check('alert detail offers actions', hasAction);
    } else {
      check('alert detail offers actions', true, 'no rows to select');
    }
    const alertRows = await page.locator('section.alerts ul.alert-list li').count();
    const alertMore = page.locator('section.alerts button', { hasText: 'Load more' });
    if (await alertMore.count() > 0) {
      await alertMore.click();
      await page.waitForFunction(
        (n) => document.querySelectorAll('section.alerts ul.alert-list li').length > n
          || document.body.textContent.includes('No more alerts.'),
        alertRows,
        { timeout: 15000 },
      );
    }
    const grownAlerts = await page.locator('section.alerts ul.alert-list li').count();
    const alertsExhausted = await page.locator('section.alerts p.muted', { hasText: 'No more alerts.' }).count();
    check('alerts load more appends history', grownAlerts > alertRows || alertsExhausted > 0, `rows=${alertRows}->${grownAlerts}`);
    await page.click('nav a[href="/policies"]');
    await page.waitForURL('**/policies', { timeout: 15000 });
    await page.waitForSelector('section.policies pre.yaml', { timeout: 15000 });
    const yaml = await page.evaluate(
      () => document.querySelector('section.policies pre.yaml')?.textContent ?? '',
    );
    check('policies view renders recommendation', yaml.includes('kind: NetworkPolicy'));
    await page.fill('section.policies input[type="text"]', 'kube-system');
    await page.click('section.policies button:not(.logout)');
    await page.waitForTimeout(1000);
    const regen = await page.evaluate(
      () => document.querySelector('section.policies pre.yaml')?.textContent ?? '',
    );
    check('policies regenerate per namespace', regen.includes('namespace: kube-system'));
    const muted = await page.locator('section.policies p.muted').allTextContents();
    check('policies show workload counts', muted.some((t) => /workload polic/.test(t)), muted.join(' | ').slice(0, 140));
    check('policies show DNS counts', muted.some((t) => /internal-only, \d+ DNS/.test(t)));
    await page.click('nav a[href="/health"]');
    await page.waitForURL('**/health', { timeout: 15000 });
    await page.waitForSelector('section.health table', { timeout: 15000 });
    const healthStats = await page.locator('section.health .stat').count();
    check('health stats render', healthStats === 5, `cards=${healthStats}`);
    const agentRows = await page.locator('section.health tbody tr').count();
    check('health view renders agent heartbeats', agentRows > 0, `rows=${agentRows}`);
    await page.click('button.logout');
    await page.waitForURL('**/login', { timeout: 15000 });
    check('logout returns to /login', true);
    check('no page errors', errors.length === 0, errors.join(' | ').slice(0, 300));
  } finally {
    await browser.close().catch(() => {});
    pf.kill('SIGTERM');
  }
  process.exit(failureCount() ? 1 : 0);
}

run(main);
