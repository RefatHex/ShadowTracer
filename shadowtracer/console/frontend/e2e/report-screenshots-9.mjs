// Phase 9: screenshot of the SOAR console (Playbooks tab — mode, shadow precision + verdict count,
// promote gate — plus the MTTD/MTTC/automation/undo metric strip).
// usage: ST_URL=.. ADMIN_EMAIL=.. ADMIN_PASSWORD=.. OUT=../../docs/report node e2e/report-screenshots-9.mjs
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

  await page.goto(`${env.ST_URL}/#/soar`)
  await page.waitForSelector('text=SOAR — automated response', { timeout: 60000 })
  await page.getByRole('button', { name: 'Playbooks' }).click()
  await page.waitForSelector('text=Shadow precision', { timeout: 60000 })
  await page.waitForTimeout(600)

  await page.locator('main').screenshot({ path: out('9-soar.png') })
  console.log('wrote', out('9-soar.png'))
} finally {
  await browser.close()
}
