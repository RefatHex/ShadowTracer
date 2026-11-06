// Phase 6.4 report screenshots of the running lab console (not a test suite).
// usage: ST_URL=https://localhost:8443 ADMIN_EMAIL=.. ADMIN_PASSWORD=.. VIEWER_EMAIL=.. VIEWER_PASSWORD=.. \
//        INCIDENT_IP=378566 INCIDENT_EICAR=394304 INCIDENT_RETRO=34008 OUT=../../docs/report node e2e/report-screenshots.mjs
// Credentials come from the environment only; nothing is written but the PNGs.
import { chromium } from '@playwright/test'

const env = process.env
const out = (name) => `${env.OUT}/${name}`

async function session(browser, email, password) {
  const page = await (await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1500, height: 1000 } })).newPage()
  await page.goto(env.ST_URL)
  await page.fill('#email', email)
  await page.fill('#password', password)
  await page.click('button[type=submit]')
  await page.waitForSelector('nav')
  return page
}

async function open(page, hash, waitFor) {
  await page.goto(`${env.ST_URL}/${hash}`)
  await page.waitForSelector(waitFor, { timeout: 60000 })
  await page.waitForTimeout(500)
}

const browser = await chromium.launch()
try {
  const admin = await session(browser, env.ADMIN_EMAIL, env.ADMIN_PASSWORD)
  await open(admin, `#/incidents/${env.INCIDENT_IP}`, 'text=Threat intel (')
  await admin.screenshot({ path: out('6.4-incident-ti-ip-match.png'), fullPage: false })

  await open(admin, `#/incidents/${env.INCIDENT_EICAR}`, 'text=Threat intel (')
  await admin.getByRole('button', { name: 'Check on VirusTotal' }).first().click()
  await admin.waitForTimeout(1500)
  await admin.screenshot({ path: out('6.4-incident-eicar-virustotal-cached.png'), fullPage: true })

  await open(admin, `#/incidents/${env.INCIDENT_RETRO}`, 'text=retro-hunt')
  await admin.screenshot({ path: out('6.4-incident-retro-hunt.png'), fullPage: false })

  await open(admin, '#/iocs', 'text=IOCs')
  await admin.selectOption('select[aria-label=type]', 'ipv4')
  await admin.click('button[type=submit]')
  await admin.waitForTimeout(1500)
  await admin.screenshot({ path: out('6.4-ioc-browser.png'), fullPage: false })

  await open(admin, '#/ti-settings', 'text=Feeds')
  await admin.screenshot({ path: out('6.4-ti-settings-admin.png'), fullPage: true })

  const viewer = await session(browser, env.VIEWER_EMAIL, env.VIEWER_PASSWORD)
  await open(viewer, '#/ti-settings', 'text=Read-only')
  await viewer.screenshot({ path: out('6.4-ti-settings-viewer-read-only.png'), fullPage: false })
  console.log('screenshots written to', env.OUT)
} finally {
  await browser.close()
}
