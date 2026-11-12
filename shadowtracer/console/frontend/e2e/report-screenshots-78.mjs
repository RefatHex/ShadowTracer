// Phase 7.8 report screenshot of the running lab console Live view, mid-attack (not a test suite).
// usage: ST_URL=https://localhost:8443 ADMIN_EMAIL=.. ADMIN_PASSWORD=.. OUT=../../docs/report \
//        node e2e/report-screenshots-78.mjs
import { chromium } from '@playwright/test'
const env = process.env
const out = (name) => `${env.OUT}/${name}`

const browser = await chromium.launch()
try {
  const page = await (await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1600, height: 1100 } })).newPage()
  await page.goto(env.ST_URL)
  await page.fill('#email', env.ADMIN_EMAIL)
  await page.fill('#password', env.ADMIN_PASSWORD)
  await page.click('button[type=submit]')
  await page.waitForSelector('nav', { timeout: 60000 })
  await page.getByRole('button', { name: 'Live', exact: true }).click()
  await page.waitForSelector('text=Live view', { timeout: 60000 })
  await page.waitForSelector('text=Stored', { timeout: 60000 })
  await page.waitForTimeout(3500)   // let a poll cycle land mid-attack
  await page.screenshot({ path: out('7.8-live-view.png'), fullPage: false })
  console.log('live-view screenshot written to', env.OUT)
} finally {
  await browser.close()
}
