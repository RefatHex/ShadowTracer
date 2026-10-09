import { useEffect, useState } from 'react'
import { useAuth } from './AuthContext'
import * as api from './api'
import type { IncidentDetail, TriageAction } from './api'

// Every field below - including alert.message, which is fully
// attacker-controlled (see AlertRow.tsx/AlertRow.test.tsx) - is rendered
// as a plain JSX text child, never dangerouslySetInnerHTML, same rule as
// the rest of this console.
export function IncidentDetailPage({ incidentId, onBack }: { incidentId: number; onBack: () => void }) {
  const { session } = useAuth()
  const [incident, setIncident] = useState<IncidentDetail | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [comment, setComment] = useState('')
  const [actionMessage, setActionMessage] = useState<string | null>(null)

  const canTriage = session?.role === 'admin' || session?.role === 'analyst'

  async function load() {
    if (!session) return
    try {
      setIncident(await api.fetchIncidentDetail(session.accessToken, incidentId))
      setError(null)
    } catch {
      setError('Could not load this incident.')
    }
  }

  useEffect(() => {
    void load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session, incidentId])

  async function handleTriage(action: TriageAction) {
    if (!session) return
    try {
      const result = await api.triageIncident(session.accessToken, incidentId, action)
      setActionMessage(
        result.suppression_state_changed_to
          ? `Triage recorded. This fingerprint is now proposed for suppression.`
          : 'Triage recorded.',
      )
      await load()
    } catch {
      setActionMessage('Could not record triage.')
    }
  }

  async function handleComment() {
    if (!session || !comment.trim()) return
    try {
      await api.commentOnIncident(session.accessToken, incidentId, comment)
      setComment('')
      setActionMessage('Comment added.')
    } catch {
      setActionMessage('Could not add comment.')
    }
  }

  if (error) return <div className="p-6 text-sm text-red-600">{error}</div>
  if (!incident) return <div className="p-6 text-sm text-gray-400">Loading…</div>

  return (
    <div className="p-6">
      <button onClick={onBack} className="mb-4 text-sm text-gray-500 hover:text-gray-700">
        ← Back to incidents
      </button>
      <h1 className="mb-1 text-lg font-semibold text-gray-900 dark:text-gray-100">
        Incident #{incident.id} — agent {incident.agent_id}
      </h1>
      <p className="mb-4 text-sm text-gray-500">
        {incident.correlation_basis} · {incident.state} · {incident.triage_status} ·{' '}
        {incident.alert_count} alerts · max level {incident.max_level}
      </p>
      {incident.rare_pattern_flag && (
        <p className="mb-4 rounded bg-purple-50 dark:bg-purple-900/30 px-3 py-2 text-sm text-purple-800 dark:text-purple-300">
          First seen for this tenant (seen {incident.prior_occurrences} time(s) before):{' '}
          {incident.rare_pattern_reason}
        </p>
      )}

      <div className="mb-6 grid grid-cols-2 gap-4 text-sm">
        <div>
          <div className="font-medium text-gray-700 dark:text-gray-300">Rule groups</div>
          <div className="text-gray-500">{incident.rule_groups.join(', ') || '—'}</div>
        </div>
        <div>
          <div className="font-medium text-gray-700 dark:text-gray-300">MITRE</div>
          <div className="text-gray-500">{incident.mitre_ids.join(', ') || '—'}</div>
        </div>
        <div>
          <div className="font-medium text-gray-700 dark:text-gray-300">Source IPs</div>
          <div className="text-gray-500">
            {incident.source_ips.join(', ') || '—'}
            {incident.source_ip_total > incident.source_ips.length && ` (+${incident.source_ip_total - incident.source_ips.length} more)`}
          </div>
        </div>
        <div>
          <div className="font-medium text-gray-700 dark:text-gray-300">Users</div>
          <div className="text-gray-500">
            {incident.users.join(', ') || '—'}
            {incident.user_total > incident.users.length && ` (+${incident.user_total - incident.users.length} more)`}
          </div>
        </div>
        {incident.fingerprint_key && (
          <div>
            <div className="font-medium text-gray-700 dark:text-gray-300">Fingerprint</div>
            <div className="break-all font-mono text-xs text-gray-500">{incident.fingerprint_key}</div>
          </div>
        )}
      </div>

      {canTriage && (
        <div className="mb-6 flex flex-wrap items-center gap-2">
          <button onClick={() => void handleTriage('acknowledge')} className="rounded bg-gray-200 dark:bg-gray-700 px-3 py-1.5 text-sm hover:bg-gray-300">
            Acknowledge
          </button>
          <button onClick={() => void handleTriage('escalate')} className="rounded bg-amber-100 px-3 py-1.5 text-sm text-amber-800 hover:bg-amber-200">
            Escalate
          </button>
          <button onClick={() => void handleTriage('false_positive')} className="rounded bg-gray-100 dark:bg-gray-700 px-3 py-1.5 text-sm hover:bg-gray-200">
            False positive
          </button>
          <input
            value={comment}
            onChange={(e) => setComment(e.target.value)}
            placeholder="Add a comment…"
            className="ml-2 flex-1 min-w-[12rem] rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900 px-2 py-1.5 text-sm"
          />
          <button onClick={() => void handleComment()} className="rounded bg-indigo-600 px-3 py-1.5 text-sm text-white hover:bg-indigo-700">
            Comment
          </button>
        </div>
      )}
      {actionMessage && <p className="mb-4 text-sm text-gray-500">{actionMessage}</p>}

      <h2 className="mb-2 text-sm font-semibold text-gray-700 dark:text-gray-300">Alerts in this incident</h2>
      <div className="overflow-hidden rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800">
        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
          <thead className="bg-gray-50 dark:bg-gray-900">
            <tr>
              <th className="px-3 py-2 text-left text-xs font-medium text-gray-500">Time</th>
              <th className="px-3 py-2 text-left text-xs font-medium text-gray-500">Rule</th>
              <th className="px-3 py-2 text-left text-xs font-medium text-gray-500">Description</th>
              <th className="px-3 py-2 text-left text-xs font-medium text-gray-500">Message</th>
            </tr>
          </thead>
          <tbody>
            {incident.alerts.map((alert) => (
              <tr key={alert.alert_id} className="border-b border-gray-200 dark:border-gray-700">
                <td className="px-3 py-2 whitespace-nowrap text-sm text-gray-500">{alert.time}</td>
                <td className="px-3 py-2 text-sm font-mono text-xs">{alert.rule_id}</td>
                <td className="px-3 py-2 text-sm">{alert.rule_description}</td>
                <td className="px-3 py-2 text-sm font-mono text-xs text-gray-600 dark:text-gray-300 break-all">{alert.message}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
