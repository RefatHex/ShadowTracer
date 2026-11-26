// Phase 9: SOAR console screenshot via `vite preview` + mocked SOAR API (robust against lab
// networking). Renders the real SoarPage (Playbooks tab) with representative data.
// usage: BASE=http://localhost:4173 OUT=../../docs/report node e2e/report-screenshots-9-mock.mjs
import { chromium } from '@playwright/test'
const env = process.env
const BASE = env.BASE || 'http://localhost:4173'
const json = (body) => ({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })

const metrics = { executions: 42, mttd_seconds: 8.4, mttc_seconds: 54.0, mean_to_execute_seconds: 11.2,
  automation_rate: 0.64, undo_rate: 0.05, false_positive_action_rate: 0.03, counts: { executed: 27, shadow: 120 } }
const playbooks = { playbooks: [
  { playbook_key: 'builtin-ssh-brute-force', title: 'SSH brute force → block IP', mode: 'auto', version: 3,
    block_seconds: 3600, precision: 0.97, verdict_count: 34, can_promote_to_auto: true, promote_blocked_reason: null,
    min_precision: 0.95, min_incidents: 20 },
  { playbook_key: 'builtin-ti-malicious-ip', title: 'TI-confirmed malicious IP → block', mode: 'approval', version: 2,
    block_seconds: 7200, precision: 0.91, verdict_count: 12, can_promote_to_auto: false,
    promote_blocked_reason: 'only 12 verdicted incidents (need 20)', min_precision: 0.95, min_incidents: 20 },
  { playbook_key: 'builtin-malware-yara', title: 'Malware / YARA hit → collect evidence + quarantine + notify',
    mode: 'shadow', version: 1, block_seconds: null, precision: null, verdict_count: 0, can_promote_to_auto: false,
    promote_blocked_reason: 'only 0 verdicted incidents (need 20)', min_precision: 0.95, min_incidents: 20 } ] }

const browser = await chromium.launch()
try {
  const ctx = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  const page = await ctx.newPage()
  await page.route('**/auth/refresh', (r) => r.fulfill(json({ access_token: 't', token_type: 'bearer', tenant_id: 10, role: 'admin' })))
  await page.route('**/api/soar/metrics', (r) => r.fulfill(json(metrics)))
  await page.route('**/api/soar/playbooks', (r) => r.fulfill(json(playbooks)))
  await page.route('**/api/soar/approvals', (r) => r.fulfill(json({ pending: [] })))
  await page.route('**/api/soar/actions', (r) => r.fulfill(json({ actions: [] })))
  await page.route('**/health', (r) => r.fulfill(json({ status: 'ok', version: '9.0' })))

  await page.goto(BASE)
  await page.waitForSelector('nav', { timeout: 60000 })
  await page.goto(`${BASE}/#/soar`)
  await page.waitForSelector('text=SOAR — automated response', { timeout: 60000 })
  await page.getByRole('button', { name: 'Playbooks' }).click()
  await page.waitForSelector('text=Shadow precision', { timeout: 60000 })
  await page.waitForTimeout(400)
  await page.locator('main').screenshot({ path: `${env.OUT}/9-soar.png` })
  console.log('wrote', `${env.OUT}/9-soar.png`)
} finally {
  await browser.close()
}
