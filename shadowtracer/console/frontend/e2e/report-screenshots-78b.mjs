// Phase 7.8 demo: screenshots of each runbook step (login, agents, live mid-attack, incident
// findings + attack graph). Not a test suite.
// usage: ST_URL=.. ADMIN_EMAIL=.. ADMIN_PASSWORD=.. INCIDENT_ID=.. OUT=../../docs/report node e2e/report-screenshots-78b.mjs
import { chromium } from '@playwright/test'
const env = process.env
const out = (name) => `${env.OUT}/${name}`

const browser = await chromium.launch()
try {
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1500, height: 1050 } })
  const page = await ctx.newPage()

  // 1. login page (logged out)
  await page.goto(env.ST_URL)
  await page.waitForSelector('#email', { timeout: 60000 })
  await page.screenshot({ path: out('7.8-step1-login.png') })

  // sign in
  await page.fill('#email', env.ADMIN_EMAIL)
  await page.fill('#password', env.ADMIN_PASSWORD)
  await page.click('button[type=submit]')
  await page.waitForSelector('nav', { timeout: 60000 })

  // 2. agents page
  await page.getByRole('button', { name: 'Agents', exact: true }).click()
  await page.waitForSelector('text=active', { timeout: 60000 })
  await page.waitForTimeout(800)
  await page.screenshot({ path: out('7.8-step2-agents.png') })

  // 3. live view mid-attack
  await page.getByRole('button', { name: 'Live', exact: true }).click()
  await page.waitForSelector('text=Live view', { timeout: 60000 })
  await page.waitForSelector('text=Stored', { timeout: 60000 })
  await page.waitForTimeout(3500)
  await page.screenshot({ path: out('7.8-step3-live-view.png') })

  // 4. an incident's findings + attack graph
  await page.goto(`${env.ST_URL}/#/incidents/${env.INCIDENT_ID}`)
  await page.waitForSelector('text=Relationship graph', { timeout: 60000 })
  await page.getByRole('button', { name: 'Build graph' }).click()
  await page.waitForFunction(() => /\d+ nodes/.test(document.body.innerText), { timeout: 60000 })
  await page.waitForTimeout(2500)
  await page.screenshot({ path: out('7.8-step4-incident-findings.png'), fullPage: true })

  console.log('screenshots written to', env.OUT)
} finally {
  await browser.close()
}
