import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App'

describe('App: login then live alert list', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('shows the login form first, then the alert list after a successful login', async () => {
    const user = userEvent.setup()
    const fetchMock = fetch as unknown as ReturnType<typeof vi.fn>

    fetchMock.mockImplementation((url: string) => {
      if (url.toString().includes('/auth/login')) {
        return Promise.resolve(
          new Response(JSON.stringify({ access_token: 'fake-token', token_type: 'bearer', tenant_id: 1, role: 'viewer' }), {
            status: 200,
          }),
        )
      }
      if (url.toString().includes('/api/alerts')) {
        return Promise.resolve(
          new Response(
            JSON.stringify({
              alerts: [
                {
                  time: '2026-01-01T00:00:00.000Z', cluster_node: 'worker1', alert_id: '1',
                  agent_id: '001', agent_name: 'agent-1', rule_id: '5710', rule_level: 5,
                  rule_description: 'sshd failure', message: 'Invalid user test',
                },
              ],
              next_cursor: null,
            }),
            { status: 200 },
          ),
        )
      }
      return Promise.resolve(new Response('{}', { status: 200 }))
    })

    render(<App />)

    // AuthContext tries a silent refresh-cookie restore on mount first -
    // with no cookie in this test, it resolves to the login form.
    await waitFor(() => expect(screen.getByLabelText(/email/i)).toBeInTheDocument())

    await user.type(screen.getByLabelText(/email/i), 'viewer@example.com')
    await user.type(screen.getByLabelText(/password/i), 'correct horse battery staple')
    await user.click(screen.getByRole('button', { name: /sign in/i }))

    await waitFor(() => expect(screen.getByText(/recent alerts/i)).toBeInTheDocument())
    await waitFor(() => expect(screen.getByText('Invalid user test')).toBeInTheDocument())
  })

  it('shows a generic error message on failed login, not the raw backend detail', async () => {
    const user = userEvent.setup()
    const fetchMock = fetch as unknown as ReturnType<typeof vi.fn>
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ detail: 'invalid credentials' }), { status: 401 }))

    render(<App />)
    await waitFor(() => expect(screen.getByLabelText(/email/i)).toBeInTheDocument())
    await user.type(screen.getByLabelText(/email/i), 'viewer@example.com')
    await user.type(screen.getByLabelText(/password/i), 'wrong')
    await user.click(screen.getByRole('button', { name: /sign in/i }))

    await waitFor(() => expect(screen.getByText(/invalid email or password/i)).toBeInTheDocument())
  })

  it('restores the session from the refresh cookie on mount, without showing the login form', async () => {
    const fetchMock = fetch as unknown as ReturnType<typeof vi.fn>

    fetchMock.mockImplementation((url: string) => {
      if (url.toString().includes('/auth/refresh')) {
        return Promise.resolve(
          new Response(JSON.stringify({ access_token: 'restored-token', token_type: 'bearer', tenant_id: 1, role: 'viewer' }), {
            status: 200,
          }),
        )
      }
      if (url.toString().includes('/api/alerts')) {
        return Promise.resolve(
          new Response(JSON.stringify({ alerts: [], next_cursor: null }), { status: 200 }),
        )
      }
      return Promise.resolve(new Response('{}', { status: 200 }))
    })

    render(<App />)

    await waitFor(() => expect(screen.getByText(/recent alerts/i)).toBeInTheDocument())
    expect(screen.queryByLabelText(/email/i)).not.toBeInTheDocument()
  })
})
