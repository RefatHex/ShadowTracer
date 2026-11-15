import { useEffect, useState } from 'react'
import { useAuth } from './AuthContext'
import * as api from './api'
import type { Campaign } from './api'
import { GraphView } from './GraphView'

// Phase 7.6 follow-up: campaigns list + the campaign relationship graph (the graph endpoint and
// GraphView existed; nothing navigated to a campaign). A campaign links incidents that share an
// attacker, so its graph shows that shared actor across them. Text-only rendering of log data.
function when(iso: string | null): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return isNaN(d.getTime()) ? iso : d.toLocaleString()
}

export function CampaignsPage() {
  const { session } = useAuth()
  const [campaigns, setCampaigns] = useState<Campaign[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [open, setOpen] = useState<Campaign | null>(null)

  useEffect(() => {
    if (!session) return
    api.fetchCampaigns(session.accessToken).then(setCampaigns).catch(() => setError('Could not load campaigns.'))
  }, [session])

  if (error) return <div className="p-6 text-sm text-red-600">{error}</div>
  if (!campaigns) return <div className="p-6 text-sm text-gray-400">Loading…</div>

  return (
    <div className="p-6">
      <h1 className="mb-1 text-lg font-semibold text-gray-900 dark:text-gray-100">Campaigns</h1>
      <p className="mb-4 text-sm text-gray-500">
        Incidents that share an attacker, linked at incident-close time. Open one to see its
        relationship graph — the shared actor across its incidents.
      </p>
      {campaigns.length === 0 ? (
        <p className="text-sm text-gray-400">No multi-incident campaigns yet.</p>
      ) : (
        <div className="overflow-hidden rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800">
          <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700 text-sm">
            <thead className="bg-gray-50 dark:bg-gray-900 text-xs text-gray-500">
              <tr>
                <th className="px-3 py-2 text-left">ID</th>
                <th className="px-3 py-2 text-left">Shared actor</th>
                <th className="px-3 py-2 text-left">Incidents</th>
                <th className="px-3 py-2 text-left">First seen</th>
                <th className="px-3 py-2 text-left">Last seen</th>
                <th className="px-3 py-2"></th>
              </tr>
            </thead>
            <tbody>
              {campaigns.map((c) => (
                <tr key={c.id} className={`border-t border-gray-100 dark:border-gray-700 ${open?.id === c.id ? 'bg-indigo-50 dark:bg-indigo-950/40' : ''}`}>
                  <td className="px-3 py-2 font-mono text-xs text-gray-500">#{c.id}</td>
                  <td className="px-3 py-2"><span className="font-mono text-xs">{c.actor_type}:{c.actor_value}</span></td>
                  <td className="px-3 py-2 font-medium text-gray-800 dark:text-gray-200">{c.incident_count}</td>
                  <td className="px-3 py-2 text-xs text-gray-500">{when(c.first_seen)}</td>
                  <td className="px-3 py-2 text-xs text-gray-500">{when(c.last_seen)}</td>
                  <td className="px-3 py-2 text-right">
                    <button onClick={() => setOpen(open?.id === c.id ? null : c)}
                      className="rounded bg-indigo-600 px-2 py-1 text-xs text-white hover:bg-indigo-700">
                      {open?.id === c.id ? 'hide graph' : 'graph'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {open && (
        <div className="mt-4">
          <h2 className="mb-1 text-sm font-semibold text-gray-700 dark:text-gray-300">
            Campaign #{open.id} — {open.actor_type}:{open.actor_value} · {open.incident_count} incidents
          </h2>
          <GraphView kind="campaign" id={open.id} />
        </div>
      )}
    </div>
  )
}
