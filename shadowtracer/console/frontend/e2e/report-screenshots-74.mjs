// Phase 7.4: screenshot of the "Model assessment" panel (XGBoost + SHAP historical classifier) on an
// incident page, showing the experimental badge, class, P(attack) and plain-language reasons.
// usage: ST_URL=.. ADMIN_EMAIL=.. ADMIN_PASSWORD=.. INCIDENT_ID=394326 OUT=../../docs/report node e2e/report-screenshots-74.mjs
import { chromium } from '@playwright/test'
const env = process.env
const out = (name) => `${env.OUT}/${name}`

const browser = await chromium.launch()
try {
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1400, height: 1100 } })
  const page = await ctx.newPage()

  await page.goto(env.ST_URL)
  await page.waitForSelector('#email', { timeout: 60000 })
  await page.fill('#email', env.ADMIN_EMAIL)
  await page.fill('#password', env.ADMIN_PASSWORD)
  await page.click('button[type=submit]')
  await page.waitForSelector('nav', { timeout: 60000 })

  await page.goto(`${env.ST_URL}/#/incidents/${env.INCIDENT_ID}`)
  // the Model assessment panel loads async (fetch at render); wait for its resolved content
  await page.waitForSelector('text=Model assessment', { timeout: 60000 })
  await page.waitForSelector('text=P(attack)', { timeout: 60000 })
  await page.waitForTimeout(600)

  const panel = page.locator('section', { has: page.getByRole('heading', { name: 'Model assessment' }) })
  await panel.scrollIntoViewIfNeeded()
  await panel.screenshot({ path: out('7.4-model-assessment.png') })
  console.log('wrote', out('7.4-model-assessment.png'))
} finally {
  await browser.close()
}
