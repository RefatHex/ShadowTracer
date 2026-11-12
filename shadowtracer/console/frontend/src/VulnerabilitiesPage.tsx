import { useEffect, useState } from 'react'
import { useAuth } from './AuthContext'
import * as api from './api'
import type { CveRow, HostVuln } from './api'

// Phase 7.7: per-host vulnerability view for the tenant. CVE inventory lands in ClickHouse via the
// indexer shim; KEV/EPSS enrichment and the KEV-first-then-EPSS sort come from the backend. All text
// is rendered as plain JSX children (never dangerouslySetInnerHTML), same rule as the rest of the console.
const PRIORITY_STYLE: Record<string, string> = {
  critical: 'bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300',
  high: 'bg-orange-100 text-orange-800 dark:bg-orange-900/40 dark:text-orange-300',
  medium: 'bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-300',
  low: 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300',
}

function pct(v: number | null): string {
  return v === null ? '—' : `${(v * 100).toFixed(1)}%`
}

function HostCves({ agentId }: { agentId: string }) {
  const { session } = useAuth()
  const [rows, setRows] = useState<CveRow[] | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!session) return
    api.fetchHostCves(session.accessToken, agentId)
      .then(setRows)
      .catch(() => setError('Could not load CVEs for this host.'))
  }, [session, agentId])

  if (error) return <p className="px-3 py-2 text-sm text-amber-700">{error}</p>
  if (!rows) return <p className="px-3 py-2 text-sm text-gray-400">Loading…</p>
  if (rows.length === 0) return <p className="px-3 py-2 text-sm text-gray-400">No open vulnerabilities.</p>

  return (
    <table className="min-w-full text-sm">
      <thead className="bg-gray-50 dark:bg-gray-900 text-xs text-gray-500">
        <tr>
          <th className="px-3 py-2 text-left">CVE</th>
          <th className="px-3 py-2 text-left">Package</th>
          <th className="px-3 py-2 text-left">Severity</th>
          <th className="px-3 py-2 text-left">CVSS</th>
          <th className="px-3 py-2 text-left">EPSS</th>
          <th className="px-3 py-2 text-left">Status</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => (
          <tr key={r.cve_id} className="border-t border-gray-100 dark:border-gray-700">
            <td className="px-3 py-2 font-mono text-xs">{r.cve_id}</td>
            <td className="px-3 py-2">{r.package_name} <span className="text-gray-400">{r.package_version}</span></td>
            <td className="px-3 py-2">{r.severity}</td>
            <td className="px-3 py-2">{r.cvss_score.toFixed(1)}</td>
            <td className="px-3 py-2">{pct(r.epss)}</td>
            <td className="px-3 py-2">
              {r.kev && (
                <span className="rounded bg-red-100 dark:bg-red-950 px-1.5 py-0.5 text-xs font-semibold text-red-800 dark:text-red-300">
                  KEV{r.kev_ransomware ? ' · ransomware' : ''}
                </span>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

export function VulnerabilitiesPage() {
  const { session } = useAuth()
  const [hosts, setHosts] = useState<HostVuln[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [open, setOpen] = useState<string | null>(null)

  useEffect(() => {
    if (!session) return
    api.fetchVulnHosts(session.accessToken)
      .then(setHosts)
      .catch(() => setError('Could not load vulnerabilities.'))
  }, [session])

  if (error) return <div className="p-6 text-sm text-red-600">{error}</div>
  if (!hosts) return <div className="p-6 text-sm text-gray-400">Loading…</div>

  return (
    <div className="p-6">
      <h1 className="mb-1 text-lg font-semibold text-gray-900 dark:text-gray-100">Vulnerabilities</h1>
      <p className="mb-4 text-sm text-gray-500">
        Per-host CVE inventory from the Wazuh vulnerability detector, sorted KEV-first (actively
        exploited) then by EPSS. <span className="text-xs opacity-70">CISA KEV (CC0) / FIRST EPSS</span>
      </p>
      {hosts.length === 0 && <p className="text-sm text-gray-400">No vulnerabilities reported yet.</p>}
      <div className="space-y-2">
        {hosts.map((h) => (
          <div key={h.agent_id} className="overflow-hidden rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800">
            <button
              onClick={() => setOpen(open === h.agent_id ? null : h.agent_id)}
              className="flex w-full items-center justify-between px-4 py-3 text-left hover:bg-gray-50 dark:hover:bg-gray-700/40"
            >
              <div className="flex items-center gap-3">
                <span className={`rounded px-2 py-0.5 text-xs font-semibold ${PRIORITY_STYLE[h.priority]}`}>
                  {h.priority}
                </span>
                <span className="font-medium text-gray-900 dark:text-gray-100">{h.agent_name}</span>
                <span className="font-mono text-xs text-gray-400">{h.agent_id}</span>
              </div>
              <div className="flex items-center gap-4 text-sm text-gray-500">
                {h.kev_count > 0 && (
                  <span className="rounded bg-red-100 dark:bg-red-950 px-1.5 py-0.5 text-xs font-semibold text-red-800 dark:text-red-300">
                    {h.kev_count} KEV
                  </span>
                )}
                <span>max EPSS {pct(h.max_epss)}</span>
                <span>max CVSS {h.max_cvss.toFixed(1)}</span>
                <span className="font-medium text-gray-700 dark:text-gray-300">{h.total} CVEs</span>
              </div>
            </button>
            {open === h.agent_id && (
              <div className="border-t border-gray-100 dark:border-gray-700 overflow-x-auto">
                <HostCves agentId={h.agent_id} />
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
