import { useEffect, useState } from 'react'
import { useAuth } from './AuthContext'
import * as api from './api'
import type { IncidentSummary, WarmupStatus } from './api'

export function IncidentsPage({ onOpen }: { onOpen: (id: number) => void }) {
  const { session } = useAuth()
  const [incidents, setIncidents] = useState<IncidentSummary[]>([])
  const [warmup, setWarmup] = useState<WarmupStatus | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!session) return
    let cancelled = false
    api.fetchIncidents(session.accessToken).then(
      (page) => { if (!cancelled) setIncidents(page.incidents) },
      () => { if (!cancelled) setError('Could not load incidents.') },
    )
    api.fetchWarmupStatus(session.accessToken).then(
      (status) => { if (!cancelled) setWarmup(status) },
      () => { /* non-critical - just don't show the banner */ },
    )
    return () => { cancelled = true }
  }, [session])

  return (
    <div className="p-6">
      <h1 className="mb-4 text-lg font-semibold text-gray-900 dark:text-gray-100">Incidents</h1>
      {warmup && !warmup.complete && (
        <p className="mb-4 rounded bg-amber-50 dark:bg-amber-900/30 px-3 py-2 text-sm text-amber-800 dark:text-amber-300">
          Rare-pattern alerting is warming up (day {warmup.days_elapsed} of {warmup.warmup_days},{' '}
          {warmup.incident_count} of {warmup.warmup_min_incidents} incidents) - no rare-pattern flags will appear
          until both thresholds are met.
        </p>
      )}
      {error && <p className="mb-4 text-sm text-red-600">{error}</p>}
      <div className="overflow-hidden rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800">
        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
          <thead className="bg-gray-50 dark:bg-gray-900">
            <tr>
              <th className="px-3 py-2 text-left text-xs font-medium text-gray-500">Agent</th>
              <th className="px-3 py-2 text-left text-xs font-medium text-gray-500">Basis</th>
              <th className="px-3 py-2 text-left text-xs font-medium text-gray-500">First seen</th>
              <th className="px-3 py-2 text-left text-xs font-medium text-gray-500">Alerts</th>
              <th className="px-3 py-2 text-left text-xs font-medium text-gray-500">Level</th>
              <th className="px-3 py-2 text-left text-xs font-medium text-gray-500">State</th>
              <th className="px-3 py-2 text-left text-xs font-medium text-gray-500">Triage</th>
              <th className="px-3 py-2 text-left text-xs font-medium text-gray-500">Rare</th>
            </tr>
          </thead>
          <tbody>
            {incidents.map((incident) => (
              <tr
                key={incident.id}
                onClick={() => onOpen(incident.id)}
                className="cursor-pointer border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700"
              >
                <td className="px-3 py-2 text-sm">{incident.agent_id}</td>
                <td className="px-3 py-2 text-sm">{incident.correlation_basis}</td>
                <td className="px-3 py-2 whitespace-nowrap text-sm text-gray-500">{incident.first_seen}</td>
                <td className="px-3 py-2 text-sm">{incident.alert_count}</td>
                <td className="px-3 py-2 text-sm">{incident.max_level}</td>
                <td className="px-3 py-2 text-sm">{incident.state}</td>
                <td className="px-3 py-2 text-sm">{incident.triage_status}</td>
                <td className="px-3 py-2 text-sm" title={incident.rare_pattern_reason ?? undefined}>
                  {incident.rare_pattern_flag && (
                    <span className="rounded bg-purple-100 dark:bg-purple-900/40 px-1.5 py-0.5 text-xs text-purple-800 dark:text-purple-300">
                      rare
                    </span>
                  )}
                </td>
              </tr>
            ))}
            {incidents.length === 0 && (
              <tr>
                <td colSpan={8} className="px-3 py-8 text-center text-sm text-gray-400">
                  No incidents yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
