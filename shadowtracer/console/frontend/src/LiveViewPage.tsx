import { useEffect, useRef, useState } from 'react'
import { useAuth } from './AuthContext'
import * as api from './api'
import type { LiveOverview } from './api'

// Phase 7.8 demo: big-screen Live view. Polls /api/live/overview and shows the pipeline stage
// counters, live tenant counters, a recent-alert ticker, incidents appearing/growing, and the
// latest TI/YARA/VT hits. All log text is rendered as plain JSX text children, never HTML.
const POLL_MS = 3000

function fmt(n: number | null | undefined): string {
  return n === null || n === undefined ? '—' : n.toLocaleString()
}
function ago(ts: number): string {
  const s = Math.max(0, Math.floor(Date.now() / 1000 - ts))
  return s < 60 ? `${s}s` : s < 3600 ? `${Math.floor(s / 60)}m` : `${Math.floor(s / 3600)}h`
}

function Stat({ label, value, accent }: { label: string; value: string; accent?: string }) {
  return (
    <div className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 px-5 py-4">
      <div className="text-xs uppercase tracking-wide text-gray-400">{label}</div>
      <div className={`mt-1 text-4xl font-bold tabular-nums ${accent ?? 'text-gray-900 dark:text-gray-100'}`}>{value}</div>
    </div>
  )
}

export function LiveViewPage() {
  const { session } = useAuth()
  const isAdmin = session?.role === 'admin'
  const [data, setData] = useState<LiveOverview | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const timer = useRef<ReturnType<typeof setInterval> | null>(null)

  async function load() {
    if (!session) return
    try { setData(await api.fetchLiveOverview(session.accessToken)); setError(null) }
    catch { setError('Could not load the Live view.') }
  }

  useEffect(() => {
    void load()
    timer.current = setInterval(() => void load(), POLL_MS)
    return () => { if (timer.current) clearInterval(timer.current) }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session])

  async function toggleDemo() {
    if (!session) return
    setBusy(true)
    try {
      const next = data?.demo.fast_close_seconds ? null : 60
      await api.setDemoFastClose(session.accessToken, next)
      await load()
    } catch { setError('Could not change the demo setting.') } finally { setBusy(false) }
  }

  if (error) return <div className="p-6 text-sm text-red-600">{error}</div>
  if (!data) return <div className="p-6 text-sm text-gray-400">Loading…</div>

  const demoOn = data.demo.fast_close_seconds !== null

  return (
    <div className="p-6">
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">Live view</h1>
        <span className="relative flex h-3 w-3"><span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-green-400 opacity-75" /><span className="relative inline-flex h-3 w-3 rounded-full bg-green-500" /></span>
        <span className="text-xs text-gray-400">updated {ago(data.as_of)} ago · every {POLL_MS / 1000}s</span>
        <div className="ml-auto flex items-center gap-2">
          <span className={`rounded-full px-3 py-1 text-xs font-semibold ${demoOn
            ? 'bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-300'
            : 'bg-gray-100 text-gray-500 dark:bg-gray-700 dark:text-gray-400'}`}>
            Demo mode: {demoOn ? `fast close ${data.demo.fast_close_seconds}s` : 'off'}
          </span>
          {isAdmin && (
            <button onClick={() => void toggleDemo()} disabled={busy}
              className="rounded bg-indigo-600 px-2 py-1 text-xs text-white hover:bg-indigo-700 disabled:opacity-50">
              {demoOn ? 'turn off' : 'fast close (60s)'}
            </button>
          )}
        </div>
      </div>

      {/* pipeline stages */}
      <div className="mb-6 flex flex-wrap items-stretch gap-2">
        {data.stages.map((s, i) => (
          <div key={s.name} className="flex items-center gap-2">
            <div className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 px-5 py-4 text-center min-w-[9rem]">
              <div className="text-xs uppercase tracking-wide text-gray-400">{s.name}</div>
              <div className="mt-1 text-3xl font-bold tabular-nums text-indigo-600 dark:text-indigo-400">{fmt(s.value)}</div>
            </div>
            {i < data.stages.length - 1 && <div className="text-2xl text-gray-300 dark:text-gray-600">→</div>}
          </div>
        ))}
      </div>

      {/* live counters */}
      <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Stat label="Events / min" value={fmt(data.events_last_min)} accent="text-indigo-600 dark:text-indigo-400" />
        <Stat label="Events total" value={fmt(data.events_total)} />
        <Stat label="Incidents open" value={fmt(data.incidents_open)} accent="text-amber-600 dark:text-amber-400" />
        <Stat label="New incidents / min" value={fmt(data.incidents_last_min)} />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* alert ticker */}
        <section className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800">
          <h2 className="border-b border-gray-100 dark:border-gray-700 px-4 py-2 text-sm font-semibold text-gray-700 dark:text-gray-300">Live alerts</h2>
          <ul className="max-h-[22rem] divide-y divide-gray-100 dark:divide-gray-700 overflow-y-auto">
            {data.recent_alerts.map((a, i) => (
              <li key={i} className="px-4 py-2 text-sm">
                <div className="flex items-center gap-2">
                  <span className={`rounded px-1.5 text-xs font-semibold ${a.rule_level >= 10 ? 'bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-300' : a.rule_level >= 7 ? 'bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300' : 'bg-gray-100 text-gray-500 dark:bg-gray-700'}`}>L{a.rule_level}</span>
                  <span className="font-mono text-xs text-gray-400">{a.rule_id}</span>
                  <span className="text-gray-700 dark:text-gray-200">{a.rule_description}</span>
                  <span className="ml-auto text-xs text-gray-400">{ago(a.time)}</span>
                </div>
                <div className="truncate font-mono text-xs text-gray-400">{a.agent_name}: {a.message}</div>
              </li>
            ))}
            {data.recent_alerts.length === 0 && <li className="px-4 py-6 text-center text-sm text-gray-400">no alerts yet</li>}
          </ul>
        </section>

        {/* incidents + hits */}
        <div className="space-y-4">
          <section className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800">
            <h2 className="border-b border-gray-100 dark:border-gray-700 px-4 py-2 text-sm font-semibold text-gray-700 dark:text-gray-300">Incidents</h2>
            <ul className="max-h-[11rem] divide-y divide-gray-100 dark:divide-gray-700 overflow-y-auto">
              {data.recent_incidents.map((inc) => (
                <li key={inc.id}>
                  <a href={`#/incidents/${inc.id}`} className="flex items-center gap-2 px-4 py-2 text-sm hover:bg-gray-50 dark:hover:bg-gray-700/40">
                    <span className="font-mono text-xs text-indigo-600 dark:text-indigo-400">#{inc.id}</span>
                    <span className="text-gray-700 dark:text-gray-200">agent {inc.agent_id}</span>
                    <span className={`rounded px-1.5 text-xs ${inc.state === 'open' ? 'bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300' : 'bg-gray-100 text-gray-500 dark:bg-gray-700'}`}>{inc.state}</span>
                    <span className="text-xs text-gray-400">{inc.alert_count} alerts · max L{inc.max_level}</span>
                    <span className="ml-auto text-xs text-indigo-500">graph →</span>
                  </a>
                </li>
              ))}
              {data.recent_incidents.length === 0 && <li className="px-4 py-6 text-center text-sm text-gray-400">no incidents yet</li>}
            </ul>
          </section>

          <section className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800">
            <h2 className="border-b border-gray-100 dark:border-gray-700 px-4 py-2 text-sm font-semibold text-gray-700 dark:text-gray-300">Latest TI / YARA / VT hits</h2>
            <ul className="max-h-[9rem] divide-y divide-gray-100 dark:divide-gray-700 overflow-y-auto">
              {data.hits.map((h, i) => (
                <li key={i} className="flex items-center gap-2 px-4 py-2 text-sm">
                  <span className="rounded bg-red-100 px-1.5 text-xs font-semibold text-red-700 dark:bg-red-950 dark:text-red-300">{h.kind}</span>
                  <span className="truncate text-gray-700 dark:text-gray-200">{h.label}</span>
                  <span className="ml-auto text-xs text-gray-400">{h.agent_name} · {ago(h.time)}</span>
                </li>
              ))}
              {data.hits.length === 0 && <li className="px-4 py-6 text-center text-sm text-gray-400">no enrichment hits yet</li>}
            </ul>
          </section>
        </div>
      </div>
    </div>
  )
}
