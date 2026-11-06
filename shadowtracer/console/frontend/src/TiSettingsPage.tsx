import { useEffect, useState } from 'react'
import { useAuth } from './AuthContext'
import * as api from './api'
import type { TiOverview, TiSettings } from './api'

// Phase 6.4: per-tenant threat-intel settings. Everyone can read; only an admin can change
// (the API answers 403 otherwise and audits every change). Keys show configured yes/no -
// their values never leave ti-sync.
export function TiSettingsPage() {
  const { session } = useAuth()
  const isAdmin = session?.role === 'admin'
  const [overview, setOverview] = useState<TiOverview | null>(null)
  const [draft, setDraft] = useState<TiSettings | null>(null)
  const [message, setMessage] = useState<string | null>(null)

  async function load() {
    if (!session) return
    try {
      const o = await api.fetchTiOverview(session.accessToken)
      setOverview(o)
      setDraft(o.settings)
    } catch {
      setMessage('Could not load threat-intel settings.')
    }
  }

  useEffect(() => {
    void load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session])

  async function save() {
    if (!session || !draft) return
    try {
      await api.updateTiSettings(session.accessToken, draft)
      setMessage('Settings saved.')
      await load()
    } catch (e) {
      setMessage(e instanceof api.ApiError && e.status === 403 ? 'Only an admin can change these settings.' : 'Could not save settings.')
    }
  }

  if (!overview || !draft) return <div className="p-6 text-sm text-gray-400">{message ?? 'Loading…'}</div>
  const toggleFeed = (name: string, on: boolean) =>
    setDraft({ ...draft, disabled_sources: on ? draft.disabled_sources.filter((n) => n !== name) : [...draft.disabled_sources, name] })
  const vt = overview.virustotal
  const yesNo = (v: boolean | undefined) => (v ? 'yes' : 'no')

  return (
    <div className="p-6">
      <h1 className="mb-4 text-lg font-semibold text-gray-900 dark:text-gray-100">Threat intel settings</h1>
      {!isAdmin && <p className="mb-4 text-sm text-gray-500">Read-only: only an admin can change these settings.</p>}
      {message && <p className="mb-4 text-sm text-gray-500">{message}</p>}

      <section className="mb-6 rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 p-4 text-sm">
        <h2 className="mb-2 font-semibold text-gray-700 dark:text-gray-300">VirusTotal</h2>
        <label className="mr-6">
          <input type="checkbox" aria-label="VirusTotal enabled" disabled={!isAdmin} checked={draft.vt_enabled}
            onChange={(e) => setDraft({ ...draft, vt_enabled: e.target.checked })} className="mr-2" />
          Send new file hashes (SHA-256 only, never files) to VirusTotal
        </label>
        <label>
          Daily budget
          <input type="number" aria-label="VirusTotal daily budget" min={0} disabled={!isAdmin} value={draft.vt_daily_budget}
            onChange={(e) => setDraft({ ...draft, vt_daily_budget: Number(e.target.value) })}
            className="ml-2 w-24 rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900 px-2 py-1" />
        </label>
        <p className="mt-2 text-gray-500">
          Key configured: {yesNo(overview.keys.virustotal)} · calls today: {vt.calls_today ?? 0} · queued: {vt.queued ?? 0} ·
          cached verdicts: {vt.cached_verdicts ?? 0}
          {vt.budget_reached && <span className="ml-2 text-amber-700">budget reached - lookups are queued</span>}
        </p>
        <p className="mt-1 text-gray-500">OTX key configured: {yesNo(overview.keys.otx)}</p>
        {overview.retro && (
          <p className="mt-1 text-gray-500">
            Retro-hunt: last run {overview.retro.last_run_at?.slice(0, 19) ?? 'never'}
            {overview.retro.last_counts.matches !== undefined && ` · ${overview.retro.last_counts.new_iocs} new IOCs, ${overview.retro.last_counts.matches} matches`}
          </p>
        )}
      </section>

      <h2 className="mb-2 text-sm font-semibold text-gray-700 dark:text-gray-300">Feeds</h2>
      <div className="overflow-hidden rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800">
        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700 text-sm">
          <thead className="bg-gray-50 dark:bg-gray-900">
            <tr>
              {['Use for this tenant', 'Feed', 'Kind', 'Last sync', 'Status', 'IOCs', 'Hits (30 d)', 'False positives (30 d)'].map((h) => (
                <th key={h} className="px-3 py-2 text-left text-xs font-medium text-gray-500">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {overview.sources.map((s) => (
              <tr key={s.name} className="border-b border-gray-200 dark:border-gray-700">
                <td className="px-3 py-2">
                  {s.private ? <span className="text-xs text-gray-500">tenant source</span> : (
                    <input type="checkbox" aria-label={`use ${s.name}`} disabled={!isAdmin || !s.enabled}
                      checked={s.enabled && !draft.disabled_sources.includes(s.name)} onChange={(e) => toggleFeed(s.name, e.target.checked)} />
                  )}
                </td>
                <td className="px-3 py-2 font-mono text-xs">{s.name}</td>
                <td className="px-3 py-2 text-xs">{s.kind}</td>
                <td className="px-3 py-2 whitespace-nowrap text-xs text-gray-500">{s.last_success_at?.slice(0, 16).replace('T', ' ') ?? '—'}</td>
                <td className="px-3 py-2 text-xs">
                  {!s.enabled ? <span className="text-gray-400">off (product default)</span>
                    : s.stale ? <span className="text-amber-700">stale{s.last_error ? ` - ${s.last_error.slice(0, 60)}` : ''}</span>
                    : <span className="text-green-700">ok</span>}
                </td>
                <td className="px-3 py-2 text-xs">{s.iocs.toLocaleString()}</td>
                <td className="px-3 py-2 text-xs">{s.hits_30d}</td>
                <td className="px-3 py-2 text-xs">
                  {s.false_positives_30d}{s.fp_rate !== null && ` (${Math.round(s.fp_rate * 100)}%)`}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {isAdmin && (
        <button onClick={() => void save()} className="mt-4 rounded bg-indigo-600 px-3 py-1.5 text-sm text-white hover:bg-indigo-700">
          Save
        </button>
      )}
    </div>
  )
}
