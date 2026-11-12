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
  rare_pattern_flag: boolean
  prior_occurrences: number | null
  rare_pattern_reason: string | null
  known_good?: boolean
  known_good_source?: string | null
  known_good_safe?: boolean
  known_good_note?: string | null
  tor_exit_ips?: string[]
  cve_ids?: string[]
  kev_cve_ids?: string[]
  max_epss?: number | null
}

export interface WarmupStatus {
  complete: boolean
  days_elapsed: number
  warmup_days: number
  incident_count: number
  warmup_min_incidents: number
  // "rare" means NOVEL here - flagged when prior occurrences <= this,
  // defaulting to 0 (strictly "first seen for this tenant").
  prior_occurrence_threshold: number
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
  ti_confidence?: number | null
  priority?: number
  ti_matches?: TiMatch[]
  drift_events?: DriftEvent[]
}

// Phase 7.2: River ADWIN behaviour-drift note (advisory).
export interface DriftEvent {
  metric: string
  before_value: number
  after_value: number
  magnitude: number
  window_start: string
}

// --- Phase 6.4: threat intel ---------------------------------------------------------
// Every string here comes from a feed or an alert: rendered as text only, links only
// through safeHttpUrl().

export interface TiSourceDetail {
  name: string
  reference_url: string | null
  source_info: string | null
}

export interface TiVerdict {
  status: string
  malicious: number
  total: number
  labels: string[]
  last_analysis: string | null
  permalink: string
}

export interface TiMatch {
  id: number
  alert_id: string
  node: string
  rule_id: string
  field: string
  observable_type: string
  observable: string
  ioc_id: number
  ioc_type: string
  ioc_value: string
  sources: string[]
  source_details: TiSourceDetail[]
  confidence: number
  origin: string
  tlp: string
  labels: string[]
  mitre: string[]
  first_seen: string
  last_seen: string
  false_positive: boolean
  virustotal: TiVerdict | null
}

export interface VtLookupResult {
  status: 'cached' | 'queued' | 'budget_reached'
  sha256?: string
  verdict?: TiVerdict & { sha256: string }
}

export interface Ioc {
  id: number
  type: string
  value: string
  scope: 'global' | 'tenant'
  tlp: string
  confidence: number
  labels: string[]
  mitre: string[]
  first_seen: string
  last_seen: string
  expires_at: string
  revoked: boolean
  sources: string[]
}

export interface IocQuery {
  q?: string
  type?: string
  source?: string
  scope?: 'all' | 'global' | 'tenant'
  min_confidence?: number
  expiry?: 'live' | 'expired' | 'all'
  limit?: number
  offset?: number
}

export interface TiSettings {
  vt_enabled: boolean
  vt_daily_budget: number
  disabled_sources: string[]
}

export interface TiOverviewSource {
  name: string
  kind: string
  private: boolean
  enabled: boolean
  last_success_at: string | null
  last_error: string | null
  iocs: number
  hits_30d: number
  false_positives_30d: number
  fp_rate: number | null
  disabled_for_tenant: boolean
  stale: boolean
}

export interface TiOverview {
  settings: TiSettings
  sources: TiOverviewSource[]
  keys: Record<string, boolean>
  virustotal: { calls_today?: number; queued?: number; budget_reached?: boolean; cached_verdicts?: number }
  retro: { cursor: string; last_run_at: string | null; last_counts: Record<string, number> } | null
}

/** Only http(s) URLs become links; anything else (javascript:, data:, ...) stays text. */
export function safeHttpUrl(value: string | null | undefined): string | null {
  if (!value) return null
  try {
    const u = new URL(value)
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.toString() : null
  } catch {
    return null
  }
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

export interface HealthResponse {
  status: string
  version: string
}

export async function fetchVersion(): Promise<HealthResponse> {
  const resp = await fetch(`${API_BASE}/health`)
  return handle<HealthResponse>(resp)
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

export async function fetchWarmupStatus(accessToken: string): Promise<WarmupStatus> {
  const resp = await fetch(`${API_BASE}/api/rare-pattern-warmup-status`, {
    headers: authHeaders(accessToken), credentials: 'include',
  })
  return handle<WarmupStatus>(resp)
}

// Phase 7.7: vulnerability view (CVE inventory landed in ClickHouse by the indexer shim,
// enriched with CISA KEV + FIRST EPSS). Hosts and CVEs come back already sorted KEV-first then EPSS.
export interface HostVuln {
  agent_id: string
  agent_name: string
  total: number
  kev_count: number
  max_epss: number | null
  max_cvss: number
  severities: Record<string, number>
  priority: 'critical' | 'high' | 'medium' | 'low'
}

export interface CveRow {
  cve_id: string
  package_name: string
  package_version: string
  severity: string
  cvss_score: number
  kev: boolean
  kev_ransomware: boolean
  epss: number | null
  epss_percentile: number | null
  first_seen: string
  last_seen: string
}

export async function fetchVulnHosts(accessToken: string): Promise<HostVuln[]> {
  const resp = await fetch(`${API_BASE}/api/vulnerabilities`, {
    headers: authHeaders(accessToken), credentials: 'include',
  })
  return handle<HostVuln[]>(resp)
}

export async function fetchHostCves(accessToken: string, agentId: string): Promise<CveRow[]> {
  const resp = await fetch(`${API_BASE}/api/vulnerabilities/hosts/${encodeURIComponent(agentId)}`, {
    headers: authHeaders(accessToken), credentials: 'include',
  })
  return handle<CveRow[]>(resp)
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


export async function vtLookup(accessToken: string, sha256: string): Promise<VtLookupResult> {
  const resp = await fetch(`${API_BASE}/api/ti/virustotal/lookups`, {
    method: 'POST', headers: { ...authHeaders(accessToken), 'Content-Type': 'application/json' },
    credentials: 'include', body: JSON.stringify({ sha256 }),
  })
  return handle<VtLookupResult>(resp)
}

export async function markFalsePositive(accessToken: string, incidentTiId: number, reason: string): Promise<{ status: string }> {
  const resp = await fetch(`${API_BASE}/api/ti/false-positives`, {
    method: 'POST', headers: { ...authHeaders(accessToken), 'Content-Type': 'application/json' },
    credentials: 'include', body: JSON.stringify({ incident_ti_id: incidentTiId, reason }),
  })
  return handle<{ status: string }>(resp)
}

export async function fetchIocs(accessToken: string, query: IocQuery): Promise<{ total: number; iocs: Ioc[] }> {
  const params = new URLSearchParams()
  for (const [k, v] of Object.entries(query)) {
    if (v !== undefined && v !== '' && v !== null) params.set(k, String(v))
  }
  const resp = await fetch(`${API_BASE}/api/ti/iocs?${params}`, { headers: authHeaders(accessToken), credentials: 'include' })
  return handle<{ total: number; iocs: Ioc[] }>(resp)
}

export async function fetchTiOverview(accessToken: string): Promise<TiOverview> {
  const resp = await fetch(`${API_BASE}/api/ti/overview`, { headers: authHeaders(accessToken), credentials: 'include' })
  return handle<TiOverview>(resp)
}

export async function updateTiSettings(accessToken: string, settings: TiSettings): Promise<TiSettings> {
  const resp = await fetch(`${API_BASE}/api/ti/settings`, {
    method: 'PUT', headers: { ...authHeaders(accessToken), 'Content-Type': 'application/json' },
    credentials: 'include', body: JSON.stringify(settings),
  })
  return handle<TiSettings>(resp)
}

// Phase 6.5 B: tenant-managed paid-source keys. The key is write-only - the API returns only a
// fingerprint/last4 for display, never the key itself.
export interface PaidSource {
  source: string
  display_name: string
  enabled: boolean
  has_key: boolean
  key_fingerprint: string | null
  key_last4: string | null
  key_version: number
  daily_budget: number
  cache_ttl_hours: number
  daily_budget_default: number
  cache_ttl_hours_default: number
  cooldown_until: string | null
  rotated_at: string | null
  updated_at: string | null
}

export interface PaidSourceUpdate {
  key?: string | null
  enabled: boolean
  daily_budget: number | null
  cache_ttl_hours: number | null
}

export async function fetchPaidSources(accessToken: string): Promise<PaidSource[]> {
  const resp = await fetch(`${API_BASE}/api/ti/paid-sources`, {
    headers: authHeaders(accessToken), credentials: 'include',
  })
  return handle<PaidSource[]>(resp)
}

export async function putPaidSource(accessToken: string, source: string, body: PaidSourceUpdate): Promise<PaidSource> {
  const resp = await fetch(`${API_BASE}/api/ti/paid-sources/${encodeURIComponent(source)}`, {
    method: 'PUT', headers: { ...authHeaders(accessToken), 'Content-Type': 'application/json' },
    credentials: 'include', body: JSON.stringify(body),
  })
  return handle<PaidSource>(resp)
}

export async function removePaidSourceKey(accessToken: string, source: string): Promise<PaidSource> {
  const resp = await fetch(`${API_BASE}/api/ti/paid-sources/${encodeURIComponent(source)}/remove`, {
    method: 'POST', headers: authHeaders(accessToken), credentials: 'include',
  })
  return handle<PaidSource>(resp)
}

// Phase 6.5 C: analyst-initiated IP reputation lookup (AbuseIPDB / GreyNoise).
export interface IpVerdict {
  source: string
  ip: string
  status: string                       // malicious | suspicious | clean | unknown
  data: Record<string, unknown>
  fetched_at: string
  served_from: string                  // live | cache
}

export async function lookupIp(accessToken: string, ip: string, source: 'abuseipdb' | 'greynoise'): Promise<IpVerdict> {
  const resp = await fetch(`${API_BASE}/api/ti/ip-lookups`, {
    method: 'POST', headers: { ...authHeaders(accessToken), 'Content-Type': 'application/json' },
    credentials: 'include', body: JSON.stringify({ ip, source }),
  })
  return handle<IpVerdict>(resp)
}

// Phase 7.6: event-relationship graph (NetworkX, on-demand).
export interface GraphNode {
  id: string; type: string; label: string
  external?: boolean | null; mitre?: string[] | null; kev?: boolean | null; colour: string
}
export interface GraphEdge {
  source: string; target: string; relation: string; count: number
  first_seen?: number | null; last_seen?: number | null
}
export interface GraphData {
  nodes: GraphNode[]; edges: GraphEdge[]
  analytics: { components: number[]; most_central_degree: string[]; most_central_betweenness: string[]; external_ip_to_host_path: string[] | null }
  summary: { capped: boolean; notes: string[]; node_count: number; edge_count: number }
  response_ms: number; cached: boolean
  shared_nodes?: [string, number[]][]; incident_count?: number; campaign_actor?: string
}

export async function fetchIncidentGraph(accessToken: string, incidentId: number): Promise<GraphData> {
  const resp = await fetch(`${API_BASE}/api/incidents/${incidentId}/graph`, { headers: authHeaders(accessToken), credentials: 'include' })
  return handle<GraphData>(resp)
}

export async function fetchCampaignGraph(accessToken: string, campaignId: number): Promise<GraphData> {
  const resp = await fetch(`${API_BASE}/api/campaigns/${campaignId}/graph`, { headers: authHeaders(accessToken), credentials: 'include' })
  return handle<GraphData>(resp)
}
