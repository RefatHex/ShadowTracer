import { useEffect, useRef, useState } from 'react'
import { AlertRow } from './AlertRow'
import { useAuth } from './AuthContext'
import * as api from './api'
import type { Alert } from './api'

const POLL_INTERVAL_MS = 5000

export function AlertsPage() {
  const { session } = useAuth()
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [error, setError] = useState<string | null>(null)
  const seenAlertIds = useRef<Set<string>>(new Set())

  useEffect(() => {
    if (!session) return

    let cancelled = false

    async function poll() {
      try {
        const page = await api.fetchAlerts(session!.accessToken)
        if (cancelled) return
        setError(null)
        // Most-recent-first page from the API; merge in anything not
        // already shown rather than replacing wholesale, so polling
        // doesn't visibly reset scroll position/flicker the list.
        const fresh = page.alerts.filter((a) => !seenAlertIds.current.has(a.alert_id))
        if (fresh.length > 0) {
          fresh.forEach((a) => seenAlertIds.current.add(a.alert_id))
          setAlerts((prev) => [...fresh, ...prev])
        }
      } catch {
        if (!cancelled) setError('Could not load alerts.')
      }
    }

    poll()
    const interval = setInterval(poll, POLL_INTERVAL_MS)
    return () => {
      cancelled = true
      clearInterval(interval)
    }
  }, [session])

  return (
    <main className="p-6">
      <h1 className="mb-4 text-lg font-semibold text-gray-900 dark:text-gray-100">Recent alerts</h1>
      {error && <p className="mb-4 text-sm text-red-600">{error}</p>}
      <div className="overflow-hidden rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800">
        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
          <thead className="bg-gray-50 dark:bg-gray-900">
            <tr>
              <th className="px-3 py-2 text-left text-xs font-medium text-gray-500">Time</th>
              <th className="px-3 py-2 text-left text-xs font-medium text-gray-500">Agent</th>
              <th className="px-3 py-2 text-left text-xs font-medium text-gray-500">Rule</th>
              <th className="px-3 py-2 text-left text-xs font-medium text-gray-500">Description</th>
              <th className="px-3 py-2 text-left text-xs font-medium text-gray-500">Message</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((a) => (
              <AlertRow key={a.alert_id} alert={a} />
            ))}
            {alerts.length === 0 && (
              <tr>
                <td colSpan={5} className="px-3 py-8 text-center text-sm text-gray-400">
                  No alerts yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </main>
  )
}
