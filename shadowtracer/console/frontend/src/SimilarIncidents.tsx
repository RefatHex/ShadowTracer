import { useEffect, useState } from 'react'
import { useAuth } from './AuthContext'
import * as api from './api'
import type { SimilarIncident } from './api'

// Phase 7.5: "Similar past incidents" - top-k by attack shape (structured-field embedding), with the
// similarity score and how each was resolved. analyst+ only. Text-only. Clicking opens that incident.
const VERDICT_STYLE: Record<string, string> = {
  false_positive: 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300',
  escalated: 'bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-300',
  acknowledged: 'bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-300',
}

export function SimilarIncidents({ incidentId }: { incidentId: number }) {
  const { session } = useAuth()
  const canView = session?.role === 'admin' || session?.role === 'analyst'
  const [items, setItems] = useState<SimilarIncident[] | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!session || !canView) return
    api.fetchSimilarIncidents(session.accessToken, incidentId)
      .then(setItems)
      .catch(() => setError('Could not load similar incidents.'))
  }, [session, incidentId, canView])

  if (!canView) return null

  return (
    <section className="mt-6">
      <h2 className="mb-2 text-sm font-semibold text-gray-700 dark:text-gray-300">Similar past incidents</h2>
      {error && <p className="text-sm text-amber-700">{error}</p>}
      {!items && !error && <p className="text-sm text-gray-400">Loading…</p>}
      {items && items.length === 0 && (
        <p className="text-sm text-gray-400">No similar past incidents yet (this one may not be indexed, or it's the first of its shape).</p>
      )}
      {items && items.length > 0 && (
        <div className="overflow-hidden rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800">
          <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700 text-sm">
            <thead className="bg-gray-50 dark:bg-gray-900 text-xs text-gray-500">
              <tr>
                <th className="px-3 py-2 text-left">Similarity</th>
                <th className="px-3 py-2 text-left">Incident</th>
                <th className="px-3 py-2 text-left">Shape</th>
                <th className="px-3 py-2 text-left">Resolved as</th>
              </tr>
            </thead>
            <tbody>
              {items.map((s) => (
                <tr key={s.incident_id} className="border-t border-gray-100 dark:border-gray-700">
                  <td className="px-3 py-2">
                    <span className="inline-block rounded bg-indigo-100 dark:bg-indigo-950 px-1.5 py-0.5 font-mono text-xs text-indigo-700 dark:text-indigo-300">
                      {(s.score * 100).toFixed(0)}%
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    <a href={`#/incidents/${s.incident_id}`} className="font-mono text-xs text-indigo-600 dark:text-indigo-400 hover:underline">
                      #{s.incident_id}
                    </a>
                    <span className="ml-2 text-xs text-gray-500">agent {s.agent_id} · max L{s.max_level}</span>
                  </td>
                  <td className="px-3 py-2 text-xs text-gray-600 dark:text-gray-300">
                    {s.correlation_basis} · {s.rule_groups.slice(0, 3).join(', ') || '—'}
                  </td>
                  <td className="px-3 py-2">
                    <span className={`rounded px-1.5 py-0.5 text-xs ${VERDICT_STYLE[s.triage_status ?? ''] ?? 'bg-gray-100 text-gray-500 dark:bg-gray-700'}`}>
                      {s.triage_status ?? 'untriaged'}
                    </span>
                    <span className="ml-2 text-xs text-gray-400">{s.state}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}
