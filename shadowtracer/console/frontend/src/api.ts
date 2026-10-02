// Thin API client. credentials: 'include' on every call so the httpOnly
// refresh cookie travels with requests to /auth/* - the access token
// itself is never stored here; callers hold it in memory only (see
// AuthContext) and pass it in explicitly.

const API_BASE = import.meta.env.VITE_API_BASE ?? ''

export interface LoginResponse {
  access_token: string
  token_type: string
  tenant_id: number
  role: string
}

export interface Alert {
  time: string
  cluster_node: string
  alert_id: string
  agent_id: string
  agent_name: string
  rule_id: string
  rule_level: number
  rule_description: string
  message: string
}

export interface AlertsPage {
  alerts: Alert[]
  next_cursor: string | null
}

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function handle<T>(resp: Response): Promise<T> {
  if (!resp.ok) {
    let detail = resp.statusText
    try {
      const body = await resp.json()
      detail = body.detail ?? detail
    } catch {
      // body wasn't JSON - fall back to statusText, never leak raw text
    }
    throw new ApiError(resp.status, detail)
  }
  return resp.json() as Promise<T>
}

export async function login(email: string, password: string): Promise<LoginResponse> {
  const resp = await fetch(`${API_BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ email, password }),
  })
  return handle<LoginResponse>(resp)
}

export async function refresh(): Promise<LoginResponse> {
  const resp = await fetch(`${API_BASE}/auth/refresh`, {
    method: 'POST',
    credentials: 'include',
  })
  return handle<LoginResponse>(resp)
}

export async function logout(): Promise<void> {
  await fetch(`${API_BASE}/auth/logout`, { method: 'POST', credentials: 'include' })
}

export async function fetchAlerts(accessToken: string, cursor?: string | null): Promise<AlertsPage> {
  const query = cursor ? `?cursor=${encodeURIComponent(cursor)}` : ''
  const resp = await fetch(`${API_BASE}/api/alerts${query}`, {
    headers: { Authorization: `Bearer ${accessToken}` },
    credentials: 'include',
  })
  return handle<AlertsPage>(resp)
}
