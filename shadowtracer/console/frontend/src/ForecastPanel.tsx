import { useEffect, useState } from 'react'
import { useAuth } from './AuthContext'
import * as api from './api'
import type { Forecast } from './api'

// Phase 7.8: "Next likely" recurrence forecast. Experimental, hint only - never drives an alert or
// suppression. Shows the predicted next window, confidence and past-occurrence timeline (forecast
// window shaded). analyst+ only (the API is analyst+); viewers see nothing.
const DOW = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']

function fmt(iso?: string): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

function howLabel(bin?: number): string {
  if (bin === undefined || bin === null) return ''
  return `${DOW[Math.floor(bin / 24)]} ${String(bin % 24).padStart(2, '0')}:00`
}

// A compact timeline: past events as dots, the forecast window shaded.
function Timeline({ events, start, end }: { events: string[]; start: string; end: string }) {
  const times = events.map((e) => Date.parse(e))
  const ps = Date.parse(start), pe = Date.parse(end)
  const t0 = Math.min(...times, ps)
  const t1 = Math.max(...times, pe)
  const span = Math.max(t1 - t0, 1)
  const W = 100, H = 24
  const x = (t: number) => ((t - t0) / span) * W
  const rectX = x(ps), rectW = Math.max(x(pe) - x(ps), 0.6)
  return (
    <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" className="mt-2 h-6 w-full" role="img"
      aria-label="past occurrences and forecast window">
      <line x1="0" y1={H / 2} x2={W} y2={H / 2} stroke="currentColor" strokeWidth="0.3" className="text-gray-300 dark:text-gray-600" />
      <rect x={rectX} y="2" width={rectW} height={H - 4} className="fill-indigo-400/30 dark:fill-indigo-500/30" />
      {times.map((t, i) => (
        <circle key={i} cx={x(t)} cy={H / 2} r="1.3" className="fill-gray-500 dark:fill-gray-300" />
      ))}
    </svg>
  )
}

export function ForecastPanel({ kind, id }: { kind: 'fingerprint' | 'campaign'; id: string | number }) {
  const { session } = useAuth()
  const canUse = session?.role === 'admin' || session?.role === 'analyst'
  const [fc, setFc] = useState<Forecast | null | undefined>(undefined)

  useEffect(() => {
    if (!session || !canUse) return
    const p = kind === 'fingerprint'
      ? api.fetchFingerprintForecast(session.accessToken, String(id))
      : api.fetchCampaignForecast(session.accessToken, Number(id))
    p.then(setFc).catch(() => setFc(null))
  }, [session, canUse, kind, id])

  if (!canUse || fc === null) return null

  const confColor = fc?.confidence === 'high' ? 'text-emerald-600 dark:text-emerald-400'
    : fc?.confidence === 'medium' ? 'text-amber-600 dark:text-amber-400'
    : 'text-gray-500'

  return (
    <section className="my-4 rounded-lg border border-indigo-200 bg-indigo-50/40 p-3 dark:border-indigo-900 dark:bg-indigo-950/30">
      <div className="mb-1 flex items-center gap-2">
        <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300">Next likely</h3>
        <span className="rounded bg-indigo-100 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-indigo-700 dark:bg-indigo-900 dark:text-indigo-300">
          Forecast (experimental, hint only)
        </span>
      </div>

      {fc === undefined && <p className="text-sm text-gray-400">Loading…</p>}

      {fc?.status === 'not_enough_history' && (
        <p className="text-sm text-gray-500">Not enough history to forecast — {fc.raw_occurrences ?? 0} occurrence(s); need ≥4 distinct events (bursts count once).</p>
      )}

      {fc?.status === 'ok' && (
        <>
          <p className="text-sm text-gray-800 dark:text-gray-200">
            <span className="font-medium">{fmt(fc.predicted_start)}</span> – <span className="font-medium">{fmt(fc.predicted_end)}</span>
            {' · '}<span className={confColor}>{fc.confidence} confidence</span>
            {' · ~'}{Math.round((fc.probability ?? 0) * 100)}% chance in window
            {' · '}{fc.occurrences} past events{fc.raw_occurrences && fc.raw_occurrences !== fc.occurrences ? ` (${fc.raw_occurrences} incidents)` : ''}
          </p>
          {fc.hour_of_week_concentration !== undefined && fc.hour_of_week_concentration >= 0.4 && (
            <p className="text-xs text-gray-500">Typically around {howLabel(fc.modal_hour_of_week)} ({Math.round((fc.hour_of_week_concentration ?? 0) * 100)}% of events)</p>
          )}
          {fc.events && fc.events.length > 0 && fc.predicted_start && fc.predicted_end && (
            <Timeline events={fc.events} start={fc.predicted_start} end={fc.predicted_end} />
          )}
          <p className="mt-1 text-[11px] text-gray-400">{fc.model_version} · computed {fmt(fc.computed_at)}</p>
        </>
      )}
    </section>
  )
}
