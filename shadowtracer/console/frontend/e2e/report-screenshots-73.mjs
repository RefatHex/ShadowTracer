// Phase 7.3: screenshot of the "Model assessment" panel showing BOTH rows - the 7.4 historical
// classifier and the 7.3 online ARF model ("Online model (River ARF)"), each marked experimental.
// usage: ST_URL=.. ADMIN_EMAIL=.. ADMIN_PASSWORD=.. INCIDENT_ID=.. OUT=../../docs/report node e2e/report-screenshots-73.mjs
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
  await page.waitForSelector('text=Model assessment', { timeout: 60000 })
  await page.waitForSelector('text=Online model (River ARF)', { timeout: 60000 })
  await page.waitForTimeout(600)

  const panel = page.locator('section', { has: page.getByRole('heading', { name: 'Model assessment' }) })
  await panel.scrollIntoViewIfNeeded()
  await panel.screenshot({ path: out('7.3-online-model.png') })
  console.log('wrote', out('7.3-online-model.png'))
} finally {
  await browser.close()
}
