// Phase 7.7: screenshot of the "AI investigation" panel on an incident page - the AI-generated summary
// with clickable evidence ids, the "AI-generated, check the evidence" label, and the evidence list.
// usage: ST_URL=.. ADMIN_EMAIL=.. ADMIN_PASSWORD=.. INCIDENT_ID=.. OUT=../../docs/report node e2e/report-screenshots-77.mjs
import { chromium } from '@playwright/test'
const env = process.env
const out = (name) => `${env.OUT}/${name}`

const browser = await chromium.launch()
try {
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1400, height: 1400 } })
  const page = await ctx.newPage()

  await page.goto(env.ST_URL)
  await page.waitForSelector('#email', { timeout: 60000 })
  await page.fill('#email', env.ADMIN_EMAIL)
  await page.fill('#password', env.ADMIN_PASSWORD)
  await page.click('button[type=submit]')
  await page.waitForSelector('nav', { timeout: 60000 })

  await page.goto(`${env.ST_URL}/#/incidents/${env.INCIDENT_ID}`)
  await page.waitForSelector('text=AI investigation', { timeout: 60000 })
  // the panel loads the stored investigation on mount; wait for the SUMMARY section to render
  await page.waitForSelector('text=SUMMARY', { timeout: 60000 })
  await page.waitForTimeout(600)

  const panel = page.locator('section', { has: page.getByRole('heading', { name: 'AI investigation' }) })
  await panel.scrollIntoViewIfNeeded()
  await panel.screenshot({ path: out('7.7-investigation.png') })
  console.log('wrote', out('7.7-investigation.png'))
} finally {
  await browser.close()
}
