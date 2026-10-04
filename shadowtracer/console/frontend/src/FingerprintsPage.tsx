import { useEffect, useState } from 'react'
import { useAuth } from './AuthContext'
import * as api from './api'
import type { FingerprintSummary } from './api'

export function FingerprintsPage({ onOpen }: { onOpen: (key: string) => void }) {
  const { session } = useAuth()
  const [fingerprints, setFingerprints] = useState<FingerprintSummary[]>([])
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!session) return
    let cancelled = false
    api.fetchFingerprints(session.accessToken).then(
      (items) => { if (!cancelled) setFingerprints(items) },
      () => { if (!cancelled) setError('Could not load the attack library.') },
    )
    return () => { cancelled = true }
  }, [session])

  return (
    <div className="p-6">
      <h1 className="mb-4 text-lg font-semibold text-gray-900 dark:text-gray-100">Attack library</h1>
      {error && <p className="mb-4 text-sm text-red-600">{error}</p>}
      <div className="overflow-hidden rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800">
        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
          <thead className="bg-gray-50 dark:bg-gray-900">
            <tr>
              <th className="px-3 py-2 text-left text-xs font-medium text-gray-500">Fingerprint</th>
              <th className="px-3 py-2 text-left text-xs font-medium text-gray-500">Label</th>
              <th className="px-3 py-2 text-left text-xs font-medium text-gray-500">Occurrences</th>
              <th className="px-3 py-2 text-left text-xs font-medium text-gray-500">Suppression</th>
            </tr>
          </thead>
          <tbody>
            {fingerprints.map((fp) => (
              <tr
                key={fp.fingerprint_key}
                onClick={() => onOpen(fp.fingerprint_key)}
                className="cursor-pointer border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700"
              >
                <td className="px-3 py-2 font-mono text-xs text-gray-600 dark:text-gray-300 break-all">
                  {fp.fingerprint_key.slice(0, 16)}…
                </td>
                <td className="px-3 py-2 text-sm">{fp.label || '—'}</td>
                <td className="px-3 py-2 text-sm">{fp.occurrence_count}</td>
                <td className="px-3 py-2 text-sm">
                  {fp.suppression_state === 'active' && (
                    <span className="rounded bg-gray-200 dark:bg-gray-700 px-1.5 py-0.5 text-xs">suppressed</span>
                  )}
                  {fp.suppression_state === 'proposed' && (
                    <span className="rounded bg-amber-100 px-1.5 py-0.5 text-xs text-amber-800">proposed</span>
                  )}
                  {fp.suppression_state === 'none' && <span className="text-gray-400">—</span>}
                </td>
              </tr>
            ))}
            {fingerprints.length === 0 && (
              <tr>
                <td colSpan={4} className="px-3 py-8 text-center text-sm text-gray-400">
                  No fingerprints yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
