// Phase 7.7 report screenshot of the running lab console vulnerability view (not a test suite).
// usage: ST_URL=https://localhost:8443 ANALYST_EMAIL=.. ANALYST_PASSWORD=.. \
//        OUT=../../docs/report node e2e/report-screenshots-77.mjs
import { chromium } from '@playwright/test'
const env = process.env
const out = (name) => `${env.OUT}/${name}`

const browser = await chromium.launch()
try {
  const page = await (await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1400, height: 1000 } })).newPage()
  await page.goto(env.ST_URL)
  await page.fill('#email', env.ANALYST_EMAIL)
  await page.fill('#password', env.ANALYST_PASSWORD)
  await page.click('button[type=submit]')
  await page.waitForSelector('nav', { timeout: 60000 })
  await page.getByRole('button', { name: 'Vulnerabilities' }).click()
  await page.waitForFunction(() => /\d+ CVEs/.test(document.body.innerText), { timeout: 60000 })
  await page.getByText(/\d+ CVEs/).first().click()   // expand the host's CVE table
  await page.waitForSelector('text=KEV', { timeout: 60000 })
  await page.waitForTimeout(800)
  await page.screenshot({ path: out('7.7-vulnerabilities.png'), fullPage: false })
  console.log('vuln screenshot written to', env.OUT)
} finally {
  await browser.close()
}
