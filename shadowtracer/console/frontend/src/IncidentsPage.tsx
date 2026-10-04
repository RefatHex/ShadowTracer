import { useEffect, useState } from 'react'
import { useAuth } from './AuthContext'
import * as api from './api'
import type { IncidentSummary } from './api'

export function IncidentsPage({ onOpen }: { onOpen: (id: number) => void }) {
  const { session } = useAuth()
  const [incidents, setIncidents] = useState<IncidentSummary[]>([])
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!session) return
    let cancelled = false
    api.fetchIncidents(session.accessToken).then(
      (page) => { if (!cancelled) setIncidents(page.incidents) },
      () => { if (!cancelled) setError('Could not load incidents.') },
    )
    return () => { cancelled = true }
  }, [session])

  return (
    <div className="p-6">
      <h1 className="mb-4 text-lg font-semibold text-gray-900 dark:text-gray-100">Incidents</h1>
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
              </tr>
            ))}
            {incidents.length === 0 && (
              <tr>
                <td colSpan={7} className="px-3 py-8 text-center text-sm text-gray-400">
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
