// Phase 7.5 report screenshot of the "Similar past incidents" section on an incident page (not a test).
// usage: ST_URL=.. ADMIN_EMAIL=.. ADMIN_PASSWORD=.. INCIDENT_ID=.. OUT=../../docs/report node e2e/report-screenshots-75.mjs
import { chromium } from '@playwright/test'
const env = process.env
const browser = await chromium.launch()
try {
  const page = await (await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1400, height: 1200 } })).newPage()
  await page.goto(env.ST_URL)
  await page.waitForSelector('#email', { timeout: 60000 })
  await page.fill('#email', env.ADMIN_EMAIL)
  await page.fill('#password', env.ADMIN_PASSWORD)
  await page.click('button[type=submit]')
  await page.waitForSelector('nav', { timeout: 60000 })
  await page.goto(`${env.ST_URL}/#/incidents/${env.INCIDENT_ID}`)
  await page.waitForSelector('text=Similar past incidents', { timeout: 60000 })
  // wait until the section has rows (a % similarity chip)
  await page.waitForFunction(() => /\d+%/.test(document.querySelector('section:has(h2)')?.parentElement?.innerText || document.body.innerText), { timeout: 60000 })
  await page.waitForTimeout(800)
  // scroll the Similar section into view and shoot
  await page.getByText('Similar past incidents').scrollIntoViewIfNeeded()
  await page.waitForTimeout(400)
  await page.screenshot({ path: `${env.OUT}/7.5-similar-incidents.png` })
  console.log('7.5-similar-incidents.png written')
} finally {
  await browser.close()
}
