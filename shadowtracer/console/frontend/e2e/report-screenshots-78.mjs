// Phase 7.8: screenshot of the "Next likely" recurrence-forecast panel on the Campaigns page - the
// predicted next window, confidence, past-events timeline (forecast window shaded) and the
// "Forecast (experimental, hint only)" label.
// usage: ST_URL=.. ADMIN_EMAIL=.. ADMIN_PASSWORD=.. CAMPAIGN_ID=37158 OUT=../../docs/report node e2e/report-screenshots-78.mjs
import { chromium } from '@playwright/test'
const env = process.env
const out = (name) => `${env.OUT}/${name}`

const browser = await chromium.launch()
try {
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1400, height: 1200 } })
  const page = await ctx.newPage()

  await page.goto(env.ST_URL)
  await page.waitForSelector('#email', { timeout: 60000 })
  await page.fill('#email', env.ADMIN_EMAIL)
  await page.fill('#password', env.ADMIN_PASSWORD)
  await page.click('button[type=submit]')
  await page.waitForSelector('nav', { timeout: 60000 })

  await page.goto(`${env.ST_URL}/#/campaigns`)
  await page.waitForSelector('text=Campaigns', { timeout: 60000 })
  // expand the target campaign's row (its "graph" button) to reveal the forecast panel
  const row = page.locator('tr', { hasText: `#${env.CAMPAIGN_ID}` }).first()
  await row.scrollIntoViewIfNeeded()
  await row.getByRole('button').click()
  await page.waitForSelector('text=Next likely', { timeout: 60000 })
  await page.waitForTimeout(600)

  const panel = page.locator('section', { has: page.getByRole('heading', { name: 'Next likely' }) })
  await panel.scrollIntoViewIfNeeded()
  await panel.screenshot({ path: out('7.8-forecast.png') })
  console.log('wrote', out('7.8-forecast.png'))
} finally {
  await browser.close()
}
