import { useEffect, useState } from 'react'
import { useAuth } from './AuthContext'
import * as api from './api'
import type { FingerprintDetail } from './api'

export function FingerprintDetailPage({ fingerprintKey, onBack }: { fingerprintKey: string; onBack: () => void }) {
  const { session } = useAuth()
  const [fp, setFp] = useState<FingerprintDetail | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [label, setLabel] = useState('')
  const [notes, setNotes] = useState('')
  const [actionMessage, setActionMessage] = useState<string | null>(null)

  const isAdmin = session?.role === 'admin'

  async function load() {
    if (!session) return
    try {
      const detail = await api.fetchFingerprintDetail(session.accessToken, fingerprintKey)
      setFp(detail)
      setLabel(detail.label ?? '')
      setNotes(detail.notes ?? '')
      setError(null)
    } catch {
      setError('Could not load this fingerprint.')
    }
  }

  useEffect(() => {
    void load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session, fingerprintKey])

  async function handleSave() {
    if (!session) return
    try {
      await api.updateFingerprint(session.accessToken, fingerprintKey, { label, notes })
      setActionMessage('Saved.')
      await load()
    } catch {
      setActionMessage('Could not save.')
    }
  }

  async function handleSuppress() {
    if (!session) return
    try {
      await api.suppressFingerprint(session.accessToken, fingerprintKey)
      setActionMessage('Suppression activated.')
      await load()
    } catch {
      setActionMessage('Could not activate suppression - it may not be in "proposed" state.')
    }
  }

  if (error) return <div className="p-6 text-sm text-red-600">{error}</div>
  if (!fp) return <div className="p-6 text-sm text-gray-400">Loading…</div>

  return (
    <div className="p-6">
      <button onClick={onBack} className="mb-4 text-sm text-gray-500 hover:text-gray-700">
        ← Back to attack library
      </button>
      <h1 className="mb-1 break-all text-lg font-semibold text-gray-900 dark:text-gray-100">
        {fp.fingerprint_key}
      </h1>
      <p className="mb-4 text-sm text-gray-500">
        {fp.occurrence_count} occurrences · suppression: {fp.suppression_state}
        {fp.suppression_expires_at && ` (expires ${fp.suppression_expires_at})`}
      </p>

      <div className="mb-6 grid grid-cols-2 gap-4 text-sm">
        <div>
          <div className="font-medium text-gray-700 dark:text-gray-300">Verdicts</div>
          <div className="text-gray-500">
            {fp.verdicts.acknowledged} acknowledged · {fp.verdicts.escalated} escalated ·{' '}
            {fp.verdicts.false_positive} false positive ({fp.verdicts.distinct_false_positive_analysts} analysts)
          </div>
        </div>
      </div>

      {isAdmin && (
        <div className="mb-6 space-y-2">
          <input
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            placeholder="Label this attack pattern…"
            className="w-full rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900 px-2 py-1.5 text-sm"
          />
          <textarea
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="Notes…"
            className="w-full rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900 px-2 py-1.5 text-sm"
            rows={3}
          />
          <div className="flex items-center gap-2">
            <button onClick={() => void handleSave()} className="rounded bg-indigo-600 px-3 py-1.5 text-sm text-white hover:bg-indigo-700">
              Save
            </button>
            {fp.suppression_state === 'proposed' && (
              <button onClick={() => void handleSuppress()} className="rounded bg-amber-600 px-3 py-1.5 text-sm text-white hover:bg-amber-700">
                Activate suppression
              </button>
            )}
          </div>
        </div>
      )}
      {!isAdmin && (fp.label || fp.notes) && (
        <div className="mb-6 text-sm">
          {fp.label && <div className="font-medium text-gray-700 dark:text-gray-300">{fp.label}</div>}
          {fp.notes && <div className="text-gray-500">{fp.notes}</div>}
        </div>
      )}
      {actionMessage && <p className="mb-4 text-sm text-gray-500">{actionMessage}</p>}

      <h2 className="mb-2 text-sm font-semibold text-gray-700 dark:text-gray-300">Occurrence history</h2>
      <div className="overflow-hidden rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800">
        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
          <thead className="bg-gray-50 dark:bg-gray-900">
            <tr>
              <th className="px-3 py-2 text-left text-xs font-medium text-gray-500">Incident</th>
              <th className="px-3 py-2 text-left text-xs font-medium text-gray-500">Closed</th>
              <th className="px-3 py-2 text-left text-xs font-medium text-gray-500">Alerts</th>
            </tr>
          </thead>
          <tbody>
            {fp.occurrences.map((occ) => (
              <tr key={occ.incident_id} className="border-b border-gray-200 dark:border-gray-700">
                <td className="px-3 py-2 text-sm">#{occ.incident_id}</td>
                <td className="px-3 py-2 whitespace-nowrap text-sm text-gray-500">{occ.closed_at}</td>
                <td className="px-3 py-2 text-sm">{occ.alert_count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
