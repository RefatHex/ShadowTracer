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

export interface IncidentSummary {
  id: number
  agent_id: string
  correlation_basis: string
  first_seen: string
  last_seen: string
  alert_count: number
  max_level: number
  state: string
  triage_status: string
  fingerprint_key: string | null
}

export interface IncidentsPage {
  incidents: IncidentSummary[]
  next_cursor: string | null
}

export interface IncidentDetail extends IncidentSummary {
  rule_ids: string[]
  rule_groups: string[]
  mitre_ids: string[]
  source_ips: string[]
  source_ip_total: number
  users: string[]
  user_total: number
  closed_at: string | null
  alerts: Alert[]
}

export type TriageAction = 'acknowledge' | 'escalate' | 'false_positive'

export interface TriageResponse {
  triage_status: string
  suppression_state_changed_to: string | null
}

export interface FingerprintSummary {
  fingerprint_key: string
  label: string | null
  suppression_state: string
  suppression_expires_at: string | null
  occurrence_count: number
}

export interface FingerprintOccurrence {
  incident_id: number
  closed_at: string
  alert_count: number
}

export interface FingerprintDetail extends FingerprintSummary {
  notes: string | null
  verdicts: {
    acknowledged: number
    escalated: number
    false_positive: number
    distinct_false_positive_analysts: number
  }
  occurrences: FingerprintOccurrence[]
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

function authHeaders(accessToken: string) {
  return { Authorization: `Bearer ${accessToken}` }
}

export async function fetchIncidents(accessToken: string, state?: 'open' | 'closed'): Promise<IncidentsPage> {
  const query = state ? `?state=${state}` : ''
  const resp = await fetch(`${API_BASE}/api/incidents${query}`, {
    headers: authHeaders(accessToken), credentials: 'include',
  })
  return handle<IncidentsPage>(resp)
}

export async function fetchIncidentDetail(accessToken: string, id: number): Promise<IncidentDetail> {
  const resp = await fetch(`${API_BASE}/api/incidents/${id}`, {
    headers: authHeaders(accessToken), credentials: 'include',
  })
  return handle<IncidentDetail>(resp)
}

export async function triageIncident(accessToken: string, id: number, action: TriageAction): Promise<TriageResponse> {
  const resp = await fetch(`${API_BASE}/api/incidents/${id}/triage`, {
    method: 'POST', headers: { ...authHeaders(accessToken), 'Content-Type': 'application/json' },
    credentials: 'include', body: JSON.stringify({ action }),
  })
  return handle<TriageResponse>(resp)
}

export async function commentOnIncident(accessToken: string, id: number, text: string): Promise<void> {
  const resp = await fetch(`${API_BASE}/api/incidents/${id}/comment`, {
    method: 'POST', headers: { ...authHeaders(accessToken), 'Content-Type': 'application/json' },
    credentials: 'include', body: JSON.stringify({ text }),
  })
  await handle<{ status: string }>(resp)
}

export async function fetchFingerprints(accessToken: string): Promise<FingerprintSummary[]> {
  const resp = await fetch(`${API_BASE}/api/fingerprints`, {
    headers: authHeaders(accessToken), credentials: 'include',
  })
  return handle<FingerprintSummary[]>(resp)
}

export async function fetchFingerprintDetail(accessToken: string, key: string): Promise<FingerprintDetail> {
  const resp = await fetch(`${API_BASE}/api/fingerprints/${encodeURIComponent(key)}`, {
    headers: authHeaders(accessToken), credentials: 'include',
  })
  return handle<FingerprintDetail>(resp)
}

export async function updateFingerprint(
  accessToken: string, key: string, body: { label?: string; notes?: string },
): Promise<void> {
  const resp = await fetch(`${API_BASE}/api/fingerprints/${encodeURIComponent(key)}`, {
    method: 'PATCH', headers: { ...authHeaders(accessToken), 'Content-Type': 'application/json' },
    credentials: 'include', body: JSON.stringify(body),
  })
  await handle<{ status: string }>(resp)
}

export async function suppressFingerprint(accessToken: string, key: string): Promise<{ suppression_state: string }> {
  const resp = await fetch(`${API_BASE}/api/fingerprints/${encodeURIComponent(key)}/suppress`, {
    method: 'POST', headers: { ...authHeaders(accessToken), 'Content-Type': 'application/json' },
    credentials: 'include', body: JSON.stringify({}),
  })
  return handle<{ suppression_state: string }>(resp)
}

export interface AttackCoverageEntry {
  tactics: string[]
  rule_ids: string[]
}

export interface AttackCoverage {
  label: string
  technique_count: number
  techniques: Record<string, AttackCoverageEntry>
}

export async function fetchAttackCoverage(accessToken: string): Promise<AttackCoverage> {
  const resp = await fetch(`${API_BASE}/api/attack-coverage`, {
    headers: authHeaders(accessToken), credentials: 'include',
  })
  return handle<AttackCoverage>(resp)
}
