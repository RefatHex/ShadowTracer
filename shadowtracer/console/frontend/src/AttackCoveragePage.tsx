import { useEffect, useState } from 'react'
import { useAuth } from './AuthContext'
import * as api from './api'
import type { AttackCoverage } from './api'

export function AttackCoveragePage() {
  const { session } = useAuth()
  const [coverage, setCoverage] = useState<AttackCoverage | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!session) return
    let cancelled = false
    api.fetchAttackCoverage(session.accessToken).then(
      (data) => { if (!cancelled) setCoverage(data) },
      () => { if (!cancelled) setError('Could not load the ATT&CK coverage map.') },
    )
    return () => { cancelled = true }
  }, [session])

  const techniques = coverage ? Object.entries(coverage.techniques).sort((a, b) => a[0].localeCompare(b[0])) : []

  return (
    <div className="p-6">
      <h1 className="mb-1 text-lg font-semibold text-gray-900 dark:text-gray-100">ATT&CK coverage map</h1>
      {coverage && (
        <p className="mb-4 max-w-2xl text-sm text-amber-700 dark:text-amber-400">
          {coverage.label}
        </p>
      )}
      {error && <p className="mb-4 text-sm text-red-600">{error}</p>}
      <div className="overflow-hidden rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800">
        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
          <thead className="bg-gray-50 dark:bg-gray-900">
            <tr>
              <th className="px-3 py-2 text-left text-xs font-medium text-gray-500">Technique</th>
              <th className="px-3 py-2 text-left text-xs font-medium text-gray-500">Tactics</th>
              <th className="px-3 py-2 text-left text-xs font-medium text-gray-500">Rules that exist</th>
            </tr>
          </thead>
          <tbody>
            {techniques.map(([techniqueId, entry]) => (
              <tr key={techniqueId} className="border-b border-gray-200 dark:border-gray-700">
                <td className="px-3 py-2 font-mono text-xs text-gray-900 dark:text-gray-100">{techniqueId}</td>
                <td className="px-3 py-2 text-sm text-gray-600 dark:text-gray-300">{entry.tactics.join(', ') || '—'}</td>
                <td className="px-3 py-2 text-sm text-gray-600 dark:text-gray-300">{entry.rule_ids.length}</td>
              </tr>
            ))}
            {coverage && techniques.length === 0 && (
              <tr>
                <td colSpan={3} className="px-3 py-8 text-center text-sm text-gray-400">
                  No techniques found.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
