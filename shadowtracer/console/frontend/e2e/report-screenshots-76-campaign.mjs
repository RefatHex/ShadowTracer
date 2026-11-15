// Phase 7.6 follow-up: screenshots of the campaign relationship graph and an incident graph from the
// running lab console (not a test suite).
// usage: ST_URL=.. ADMIN_EMAIL=.. ADMIN_PASSWORD=.. INCIDENT_ID=.. OUT=../../docs/report node e2e/report-screenshots-76-campaign.mjs
import { chromium } from '@playwright/test'
const env = process.env
const out = (name) => `${env.OUT}/${name}`

const browser = await chromium.launch()
try {
  const page = await (await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1500, height: 1050 } })).newPage()
  await page.goto(env.ST_URL)
  await page.waitForSelector('#email', { timeout: 60000 })
  await page.fill('#email', env.ADMIN_EMAIL)
  await page.fill('#password', env.ADMIN_PASSWORD)
  await page.click('button[type=submit]')
  await page.waitForSelector('nav', { timeout: 60000 })

  // campaign graph: open Campaigns, click the first campaign's graph
  await page.getByRole('button', { name: 'Campaigns', exact: true }).click()
  await page.waitForSelector('text=Shared actor', { timeout: 60000 })
  await page.getByRole('button', { name: 'graph', exact: true }).first().click()
  await page.waitForSelector('text=Relationship graph', { timeout: 60000 })
  await page.getByRole('button', { name: 'Build graph' }).click()
  await page.waitForFunction(() => /\d+ nodes/.test(document.body.innerText), { timeout: 60000 })
  await page.waitForTimeout(2500)
  await page.screenshot({ path: out('7.6-campaign-graph.png'), fullPage: false })
  console.log('campaign graph screenshot written')

  // incident graph (refresh the existing report shot) if an id was given
  if (env.INCIDENT_ID) {
    await page.goto(`${env.ST_URL}/#/incidents/${env.INCIDENT_ID}`)
    await page.waitForSelector('text=Relationship graph', { timeout: 60000 })
    await page.getByRole('button', { name: 'Build graph' }).click()
    await page.waitForFunction(() => /\d+ nodes/.test(document.body.innerText), { timeout: 60000 })
    await page.waitForTimeout(2500)
    await page.screenshot({ path: out('7.6-incident-graph-brute-force.png'), fullPage: false })
    console.log('incident graph screenshot refreshed')
  }
} finally {
  await browser.close()
}
