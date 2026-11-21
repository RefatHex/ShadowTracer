import { useEffect, useState } from 'react'
import { useAuth } from './AuthContext'
import * as api from './api'
import type { ModelAssessment as Assessment } from './api'

// Phase 7.4: "Model assessment" - the XGBoost historical classifier's class + probability + SHAP
// reasons for this incident. analyst+ only. Shown strictly as an ADVISORY HINT: it never filters,
// suppresses or auto-closes an incident. Text-only.
export function ModelAssessment({ incidentId }: { incidentId: number }) {
  const { session } = useAuth()
  const canView = session?.role === 'admin' || session?.role === 'analyst'
  const [item, setItem] = useState<Assessment | null | undefined>(undefined)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!session || !canView) return
    api.fetchModelAssessment(session.accessToken, incidentId)
      .then(setItem)
      .catch(() => setError('Could not load the model assessment.'))
  }, [session, incidentId, canView])

  if (!canView) return null

  const isAttack = item?.predicted_class === 'attack'
  return (
    <section className="mt-6">
      <div className="mb-2 flex items-center gap-2">
        <h2 className="text-sm font-semibold text-gray-700 dark:text-gray-300">Model assessment</h2>
        {item?.experimental && (
          <span className="rounded bg-amber-100 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-amber-700 dark:bg-amber-950 dark:text-amber-300">
            experimental
          </span>
        )}
        <span className="rounded bg-gray-100 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-gray-500 dark:bg-gray-700 dark:text-gray-400">
          advisory hint
        </span>
      </div>
      {error && <p className="text-sm text-amber-700">{error}</p>}
      {item === undefined && !error && <p className="text-sm text-gray-400">Loading…</p>}
      {item === null && (
        <p className="text-sm text-gray-400">
          Not scored by the historical classifier yet (it scores incidents at close; this one may predate the model).
        </p>
      )}
      {item && (
        <div className="rounded-lg border border-gray-200 bg-white p-4 dark:border-gray-700 dark:bg-gray-800">
          <div className="flex flex-wrap items-center gap-3">
            <span className={`rounded px-2 py-0.5 text-sm font-semibold ${isAttack
              ? 'bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-300'
              : 'bg-emerald-100 text-emerald-700 dark:bg-emerald-950 dark:text-emerald-300'}`}>
              {isAttack ? 'Likely attack' : 'Likely benign'}
            </span>
            <span className="font-mono text-sm text-gray-600 dark:text-gray-300">
              P(attack) {(item.probability * 100).toFixed(0)}%
            </span>
            <span className="text-xs text-gray-400">{item.model_version}</span>
          </div>
          {item.reasons.length > 0 && (
            <ul className="mt-3 space-y-1">
              {item.reasons.map((r, i) => (
                <li key={i} className="text-sm text-gray-600 dark:text-gray-300">· {r}</li>
              ))}
            </ul>
          )}
          {item.online && (
            <div className="mt-3 border-t border-gray-100 pt-3 dark:border-gray-700">
              <div className="mb-1 flex items-center gap-2">
                <span className="text-xs font-medium text-gray-500 dark:text-gray-400">Online model (River ARF)</span>
                <span className="rounded bg-amber-100 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-amber-700 dark:bg-amber-950 dark:text-amber-300">
                  experimental
                </span>
              </div>
              <div className="flex flex-wrap items-center gap-3">
                <span className={`rounded px-2 py-0.5 text-sm font-semibold ${item.online.predicted_class === 'attack'
                  ? 'bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-300'
                  : 'bg-emerald-100 text-emerald-700 dark:bg-emerald-950 dark:text-emerald-300'}`}>
                  {item.online.predicted_class === 'attack' ? 'Likely attack' : 'Likely benign'}
                </span>
                <span className="font-mono text-sm text-gray-600 dark:text-gray-300">
                  P(attack) {(item.online.probability * 100).toFixed(0)}%
                </span>
                <span className="text-xs text-gray-400">{item.online.model_version}</span>
              </div>
            </div>
          )}
          <p className="mt-3 text-xs text-gray-400">
            Advisory only — this assessment never filters, suppresses or auto-closes an incident.
          </p>
        </div>
      )}
    </section>
  )
}
