// Phase 6.5 report screenshots of the running lab console (not a test suite). Reuses the 6.4 approach.
// usage: ST_URL=https://localhost:8443 VIEWER_EMAIL=.. VIEWER_PASSWORD=.. ANALYST_EMAIL=.. ANALYST_PASSWORD=.. \
//        INCIDENT_VERDICTS=378566 INCIDENT_CVE=482905 OUT=../../docs/report node e2e/report-screenshots-65.mjs
// Credentials come from the environment only; nothing is written but the PNGs.
import { chromium } from '@playwright/test'

const env = process.env
const out = (name) => `${env.OUT}/${name}`

async function session(browser, email, password) {
  const page = await (await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1500, height: 1100 } })).newPage()
  await page.goto(env.ST_URL)
  await page.fill('#email', email)
  await page.fill('#password', password)
  await page.click('button[type=submit]')
  await page.waitForSelector('nav', { timeout: 60000 })
  return page
}

async function open(page, hash, waitFor) {
  await page.goto(`${env.ST_URL}/${hash}`)
  await page.waitForSelector(waitFor, { timeout: 60000 })
  await page.waitForTimeout(700)
}

const browser = await chromium.launch()
try {
  const viewer = await session(browser, env.VIEWER_EMAIL, env.VIEWER_PASSWORD)

  // 1. TI settings -> Paid sources (write-only: only ••••last4 + version shown, read-only for a viewer)
  await open(viewer, '#/ti-settings', 'text=Paid sources')
  await viewer.screenshot({ path: out('6.5-ti-settings-paid-sources.png'), fullPage: true })

  // 2. incident with known-good / MalwareBazaar / VirusTotal verdicts
  await open(viewer, `#/incidents/${env.INCIDENT_VERDICTS}`, 'text=known file in unusual location')
  await viewer.screenshot({ path: out('6.5-incident-known-good-mbz-vt.png'), fullPage: true })

  // 3. incident with the CVE / KEV (actively exploited) / EPSS badge
  await open(viewer, `#/incidents/${env.INCIDENT_CVE}`, 'text=CISA KEV')
  await viewer.screenshot({ path: out('6.5-incident-cve-kev-epss.png'), fullPage: true })

  // 4. per-IP AbuseIPDB / GreyNoise lookup buttons (analyst role sees the buttons; a viewer does not)
  const analyst = await session(browser, env.ANALYST_EMAIL, env.ANALYST_PASSWORD)
  await open(analyst, `#/incidents/${env.INCIDENT_VERDICTS}`, 'text=AbuseIPDB')
  await analyst.screenshot({ path: out('6.5-incident-ip-lookup-buttons.png'), fullPage: true })

  console.log('screenshots written to', env.OUT)
} finally {
  await browser.close()
}
