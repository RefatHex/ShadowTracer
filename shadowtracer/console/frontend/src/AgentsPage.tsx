import { useEffect, useState } from 'react'
import { useAuth } from './AuthContext'
import * as api from './api'
import type { Agent } from './api'

// Phase 7.8 demo: Agents for the tenant, from its Wazuh manager API (name, OS, status, last seen,
// manager, tenant). All values render as plain text children. Read-only.
const STATUS_STYLE: Record<string, string> = {
  active: 'bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300',
  disconnected: 'bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-300',
  never_connected: 'bg-gray-100 text-gray-500 dark:bg-gray-700 dark:text-gray-400',
  pending: 'bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-300',
}

function when(iso: string | null): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (isNaN(d.getTime())) return iso
  const s = Math.max(0, Math.floor((Date.now() - d.getTime()) / 1000))
  return s < 60 ? `${s}s ago` : s < 3600 ? `${Math.floor(s / 60)}m ago` : s < 86400 ? `${Math.floor(s / 3600)}h ago` : d.toLocaleString()
}

export function AgentsPage() {
  const { session } = useAuth()
  const [agents, setAgents] = useState<Agent[] | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!session) return
    api.fetchAgents(session.accessToken)
      // active agents first (the live ones a demo cares about), then by id
      .then((rows) => [...rows].sort((a, b) =>
        (a.status === 'active' ? 0 : 1) - (b.status === 'active' ? 0 : 1) || a.id.localeCompare(b.id)))
      .then(setAgents)
      .catch(() => setError('Could not load agents.'))
  }, [session])

  if (error) return <div className="p-6 text-sm text-red-600">{error}</div>
  if (!agents) return <div className="p-6 text-sm text-gray-400">Loading…</div>

  const active = agents.filter((a) => a.status === 'active').length

  return (
    <div className="p-6">
      <h1 className="mb-1 text-lg font-semibold text-gray-900 dark:text-gray-100">Agents</h1>
      <p className="mb-4 text-sm text-gray-500">
        {agents.length} agents · {active} active — from this tenant's Wazuh manager.
      </p>
      {agents.length === 0 ? (
        <p className="text-sm text-gray-400">No agents reported. (The tenant's manager API must be configured for this view.)</p>
      ) : (
        <div className="overflow-hidden rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800">
          <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700 text-sm">
            <thead className="bg-gray-50 dark:bg-gray-900 text-xs text-gray-500">
              <tr>
                <th className="px-3 py-2 text-left">ID</th>
                <th className="px-3 py-2 text-left">Name</th>
                <th className="px-3 py-2 text-left">OS</th>
                <th className="px-3 py-2 text-left">Status</th>
                <th className="px-3 py-2 text-left">Last seen</th>
                <th className="px-3 py-2 text-left">Manager</th>
                <th className="px-3 py-2 text-left">Tenant</th>
              </tr>
            </thead>
            <tbody>
              {agents.map((a) => (
                <tr key={a.id} className="border-t border-gray-100 dark:border-gray-700">
                  <td className="px-3 py-2 font-mono text-xs text-gray-500">{a.id}</td>
                  <td className="px-3 py-2 text-gray-800 dark:text-gray-200">{a.name}</td>
                  <td className="px-3 py-2">{a.os}</td>
                  <td className="px-3 py-2">
                    <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${STATUS_STYLE[a.status] ?? 'bg-gray-100 text-gray-500 dark:bg-gray-700'}`}>
                      {a.status}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-gray-500">{when(a.last_seen)}</td>
                  <td className="px-3 py-2 text-gray-500">{a.manager}</td>
                  <td className="px-3 py-2 font-mono text-xs text-gray-400">{a.tenant.slice(0, 8)}…</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
