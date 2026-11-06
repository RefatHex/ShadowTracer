import { render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { AuthProvider } from './AuthContext'
import type { TiMatch } from './api'
import { TiSection } from './TiSection'
import { TiSettingsPage } from './TiSettingsPage'

// Phase 6.4: feed data (tags, pulse names, source links) is attacker-influenced: anyone can
// publish an OTX pulse or a MISP event. It must render as text, and only http(s) links.
const XSS = '<img src=x onerror="window.__ti_xss_fired = true">'

function stubFetch(role: string, extra: (url: string) => Response | null = () => null) {
  vi.stubGlobal('fetch', vi.fn((url: string) => {
    if (url.toString().includes('/auth/refresh')) {
      return Promise.resolve(new Response(JSON.stringify({ access_token: 't', token_type: 'bearer', tenant_id: 1, role }), { status: 200 }))
    }
    return Promise.resolve(extra(url.toString()) ?? new Response('{}', { status: 200 }))
  }))
}

const match: TiMatch = {
  id: 7, alert_id: '1.1', node: 'worker-test', rule_id: '5710', field: 'data.srcip', observable_type: 'sha256',
  observable: 'a'.repeat(64), ioc_id: 3, ioc_type: 'sha256', ioc_value: 'a'.repeat(64), sources: ['otx'],
  source_details: [
    { name: 'otx', reference_url: 'javascript:window.__ti_xss_fired=true', source_info: XSS },
    { name: 'abusech-feodo', reference_url: 'https://feodotracker.abuse.ch/browse/host/1.2.3.4/', source_info: null },
  ],
  confidence: 90, origin: 'matcher', tlp: 'clear', labels: [XSS], mitre: ['T1071'], first_seen: '2026-11-01T00:00:00Z',
  last_seen: '2026-11-06T00:00:00Z', false_positive: false,
  virustotal: { status: 'malicious', malicious: 62, total: 64, labels: [XSS], last_analysis: '2026-11-06T03:49:51Z',
    permalink: 'https://www.virustotal.com/gui/file/' + 'a'.repeat(64) },
}

describe('TiSection', () => {
  beforeEach(() => { (window as unknown as Record<string, unknown>).__ti_xss_fired = false })
  afterEach(() => vi.unstubAllGlobals())

  it('renders feed text literally and links only http(s) URLs', async () => {
    stubFetch('analyst')
    render(<AuthProvider><TiSection matches={[match]} onChanged={() => {}} /></AuthProvider>)
    await waitFor(() => expect(screen.getByText('Check on VirusTotal')).toBeInTheDocument())
    expect(document.querySelector('img')).toBeNull()
    expect(screen.getAllByText(new RegExp(XSS.slice(0, 8))).length).toBeGreaterThan(0)
    const links = Array.from(document.querySelectorAll('a')).map((a) => a.getAttribute('href'))
    expect(links).toContain('https://feodotracker.abuse.ch/browse/host/1.2.3.4/')
    expect(links.some((h) => h?.startsWith('javascript:'))).toBe(false)
    expect(screen.getByText(/VirusTotal: malicious 62\/64/)).toBeInTheDocument()
    expect(screen.getByText('Mark false positive')).toBeInTheDocument()
    expect((window as unknown as Record<string, unknown>).__ti_xss_fired).toBe(false)
  })

  it('gives a viewer no actions', async () => {
    stubFetch('viewer')
    render(<AuthProvider><TiSection matches={[match]} onChanged={() => {}} /></AuthProvider>)
    await waitFor(() => expect(screen.getByText(/VirusTotal: malicious/)).toBeInTheDocument())
    expect(screen.queryByText('Check on VirusTotal')).toBeNull()
    expect(screen.queryByText('Mark false positive')).toBeNull()
  })
})

describe('TiSettingsPage', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('is read-only for a viewer', async () => {
    stubFetch('viewer', (url) => url.includes('/api/ti/overview') ? new Response(JSON.stringify({
      settings: { vt_enabled: true, vt_daily_budget: 500, disabled_sources: [] },
      sources: [{ name: 'abusech-feodo', kind: 'feodo', private: false, enabled: true, last_success_at: null, last_error: null,
        iocs: 5, hits_30d: 0, false_positives_30d: 0, fp_rate: null, disabled_for_tenant: false, stale: false }],
      keys: { virustotal: true, otx: true }, virustotal: { calls_today: 2 }, retro: null,
    }), { status: 200 }) : null)
    render(<AuthProvider><TiSettingsPage /></AuthProvider>)
    await waitFor(() => expect(screen.getByText('abusech-feodo')).toBeInTheDocument())
    expect(screen.getByText(/Read-only/)).toBeInTheDocument()
    expect(screen.queryByText('Save')).toBeNull()
    expect((screen.getByLabelText('VirusTotal enabled') as HTMLInputElement).disabled).toBe(true)
    expect(screen.getByText(/Key configured: yes/)).toBeInTheDocument()
  })
})
