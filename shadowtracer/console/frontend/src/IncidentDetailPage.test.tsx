import { render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { AuthProvider } from './AuthContext'
import { IncidentDetailPage } from './IncidentDetailPage'

// Same property as AlertRow.test.tsx, proven on the incident detail
// screen specifically - an incident's alerts carry the exact same
// attacker-controlled message field, rendered here independently.
describe('IncidentDetailPage renders attacker-controlled alert text safely', () => {
  const XSS_PAYLOAD = '<script>window.__incident_xss_fired = true</script><img src=x onerror="window.__incident_xss_fired = true">'

  beforeEach(() => {
    ;(window as unknown as Record<string, unknown>).__incident_xss_fired = false
    vi.stubGlobal('fetch', vi.fn((url: string) => {
      if (url.toString().includes('/auth/refresh')) {
        return Promise.resolve(
          new Response(
            JSON.stringify({ access_token: 'fake-token', token_type: 'bearer', tenant_id: 1, role: 'analyst' }),
            { status: 200 },
          ),
        )
      }
      if (url.toString().includes('/api/incidents/42')) {
        return Promise.resolve(
          new Response(
            JSON.stringify({
              id: 42, agent_id: 'agent-1', correlation_basis: 'source_ip',
              first_seen: '2026-01-01T00:00:00.000Z', last_seen: '2026-01-01T00:01:00.000Z',
              alert_count: 1, max_level: 5, state: 'open', triage_status: 'new', fingerprint_key: null,
              rule_ids: [], rule_groups: [], mitre_ids: [], source_ips: [], source_ip_total: 0,
              users: [], user_total: 0, closed_at: null,
              alerts: [{
                time: '2026-01-01T00:00:00.000Z', cluster_node: 'worker1', alert_id: '1',
                agent_id: '001', agent_name: 'agent-1', rule_id: '5710', rule_level: 5,
                rule_description: 'test', message: XSS_PAYLOAD,
              }],
            }),
            { status: 200 },
          ),
        )
      }
      return Promise.resolve(new Response('{}', { status: 200 }))
    }))
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('does not execute the payload and shows it as literal text', async () => {
    render(
      <AuthProvider>
        <IncidentDetailPage incidentId={42} onBack={() => {}} />
      </AuthProvider>,
    )

    await waitFor(() => expect(screen.getByText(/Incident #42/)).toBeInTheDocument())

    expect(document.querySelector('script')).toBeNull()
    expect(document.querySelector('img')).toBeNull()
    expect((window as unknown as Record<string, unknown>).__incident_xss_fired).toBe(false)
    expect(screen.getByText(XSS_PAYLOAD)).toBeInTheDocument()
  })
})
