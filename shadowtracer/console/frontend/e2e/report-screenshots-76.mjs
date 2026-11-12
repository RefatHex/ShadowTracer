// Phase 7.6 report screenshots of the running lab console graph (not a test suite).
// usage: ST_URL=https://localhost:8443 ANALYST_EMAIL=.. ANALYST_PASSWORD=.. BRUTE=483444 FIMYARA=378566 \
//        OUT=../../docs/report node e2e/report-screenshots-76.mjs
import { chromium } from '@playwright/test'
const env = process.env
const out = (name) => `${env.OUT}/${name}`

async function session(browser, email, password) {
  const page = await (await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1500, height: 1100 } })).newPage()
  await page.goto(env.ST_URL)
  await page.fill('#email', email); await page.fill('#password', password)
  await page.click('button[type=submit]')
  await page.waitForSelector('nav', { timeout: 60000 })
  return page
}

async function graphShot(page, incidentId, name) {
  await page.goto(`${env.ST_URL}/#/incidents/${incidentId}`)
  await page.waitForSelector('text=Relationship graph', { timeout: 60000 })
  await page.getByRole('button', { name: 'Build graph' }).click()
  await page.waitForFunction(() => /\d+ nodes · \d+ edges/.test(document.body.innerText), { timeout: 60000 })
  await page.waitForTimeout(2500)          // let the cose layout settle
  await page.screenshot({ path: out(name), fullPage: false })
}

const browser = await chromium.launch()
try {
  const a = await session(browser, env.ANALYST_EMAIL, env.ANALYST_PASSWORD)
  await graphShot(a, env.BRUTE, '7.6-incident-graph-brute-force.png')
  await graphShot(a, env.FIMYARA, '7.6-incident-graph-fim-yara-ti.png')
  console.log('graph screenshots written to', env.OUT)
} finally {
  await browser.close()
}
