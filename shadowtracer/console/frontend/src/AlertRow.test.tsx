import { render } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { AlertRow } from './AlertRow'
import type { Alert } from './api'

// Step 6's required test: an alert whose full_log contains a script tag
// and an onerror image must render as inert text, nothing executed,
// nothing injected into the DOM as real markup.
describe('AlertRow renders attacker-controlled text safely', () => {
  const maliciousAlert: Alert = {
    time: '2026-01-01T00:00:00.000Z',
    cluster_node: 'worker1',
    alert_id: '123.456',
    agent_id: '001',
    agent_name: '<b>bold-agent</b>',
    rule_id: '5710',
    rule_level: 5,
    rule_description: 'sshd: attempt to login',
    message:
      'Invalid user <script>window.__xss_fired = true</script>' +
      '<img src="x" onerror="window.__xss_fired = true">' +
      ' from 10.0.0.1',
  }

  it('does not create a real <script> element anywhere in the rendered output', () => {
    const { container } = render(
      <table>
        <tbody>
          <AlertRow alert={maliciousAlert} />
        </tbody>
      </table>,
    )
    expect(container.querySelectorAll('script')).toHaveLength(0)
  })

  it('does not create a real <img> element (onerror never gets a chance to fire)', () => {
    const { container } = render(
      <table>
        <tbody>
          <AlertRow alert={maliciousAlert} />
        </tbody>
      </table>,
    )
    expect(container.querySelectorAll('img')).toHaveLength(0)
  })

  it('never actually executes the injected script/onerror payload', () => {
    const win = window as unknown as { __xss_fired?: boolean }
    win.__xss_fired = false

    render(
      <table>
        <tbody>
          <AlertRow alert={maliciousAlert} />
        </tbody>
      </table>,
    )

    expect(win.__xss_fired).toBe(false)
  })

  it('shows the payload as visible, literal text instead of silently dropping it', () => {
    const { getByText } = render(
      <table>
        <tbody>
          <AlertRow alert={maliciousAlert} />
        </tbody>
      </table>,
    )
    // The raw text (including the literal "<script>" characters) must be
    // present as PLAIN TEXT - proving it was rendered, not stripped, and
    // not interpreted as markup.
    expect(getByText(/Invalid user <script>window\.__xss_fired = true<\/script>/)).toBeInTheDocument()
  })

  it('does not inject markup for attacker-controlled fields other than message either', () => {
    const { container } = render(
      <table>
        <tbody>
          <AlertRow alert={maliciousAlert} />
        </tbody>
      </table>,
    )
    expect(container.querySelectorAll('b').length).toBe(0)
    expect(container.textContent).toContain('<b>bold-agent</b>')
  })
})
