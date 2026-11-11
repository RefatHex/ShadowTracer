import { useEffect, useState } from 'react'
import { useAuth } from './AuthContext'
import * as api from './api'
import type { PaidSource } from './api'

// Phase 6.5 B: tenant-managed paid-source API keys. Admin-only writes (the API answers 403
// otherwise and audits every change). Keys are write-only: the field is never pre-filled and its
// value is sent once to be sealed; the UI only ever shows a fingerprint/last-4, never the key.
export function PaidSourcesSection() {
  const { session } = useAuth()
  const isAdmin = session?.role === 'admin'
  const [sources, setSources] = useState<PaidSource[] | null>(null)
  const [keyDraft, setKeyDraft] = useState<Record<string, string>>({})
  const [message, setMessage] = useState<string | null>(null)

  async function load() {
    if (!session) return
    try {
      setSources(await api.fetchPaidSources(session.accessToken))
    } catch {
      setMessage('Could not load paid sources.')
    }
  }

  useEffect(() => {
    void load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session])

  function err(e: unknown, fallback: string): string {
    if (e instanceof api.ApiError) {
      if (e.status === 403) return 'Only an admin can change paid-source keys.'
      if (e.status === 503) return 'Paid-key management is not configured (no KEY_ENCRYPTION_KEY).'
      return e.message
    }
    return fallback
  }

  async function save(s: PaidSource, patch: Partial<api.PaidSourceUpdate>) {
    if (!session) return
    const key = keyDraft[s.source]?.trim()
    const body: api.PaidSourceUpdate = {
      enabled: patch.enabled ?? s.enabled,
      daily_budget: patch.daily_budget !== undefined ? patch.daily_budget : s.daily_budget,
      cache_ttl_hours: patch.cache_ttl_hours !== undefined ? patch.cache_ttl_hours : s.cache_ttl_hours,
      ...(key ? { key } : {}),
    }
    try {
      await api.putPaidSource(session.accessToken, s.source, body)
      setKeyDraft({ ...keyDraft, [s.source]: '' })
      setMessage(`${s.display_name}: saved.`)
      await load()
    } catch (e) {
      setMessage(`${s.display_name}: ${err(e, 'could not save.')}`)
    }
  }

  async function removeKey(s: PaidSource) {
    if (!session) return
    try {
      await api.removePaidSourceKey(session.accessToken, s.source)
      setMessage(`${s.display_name}: key removed.`)
      await load()
    } catch (e) {
      setMessage(`${s.display_name}: ${err(e, 'could not remove key.')}`)
    }
  }

  if (!sources) return <p className="text-sm text-gray-400">{message ?? 'Loading paid sources…'}</p>

  return (
    <section className="mb-6">
      <h2 className="mb-2 text-sm font-semibold text-gray-700 dark:text-gray-300">Paid sources (your own API keys)</h2>
      {!isAdmin && <p className="mb-2 text-sm text-gray-500">Read-only: only an admin can set keys.</p>}
      {message && <p className="mb-2 text-sm text-gray-500">{message}</p>}
      <div className="overflow-hidden rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800">
        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700 text-sm">
          <thead className="bg-gray-50 dark:bg-gray-900">
            <tr>
              {['Source', 'Key', 'Enabled', 'Daily budget', 'Cache (h)', 'Set / rotate key', ''].map((h) => (
                <th key={h} className="px-3 py-2 text-left text-xs font-medium text-gray-500">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sources.map((s) => (
              <tr key={s.source} className="border-b border-gray-200 dark:border-gray-700 align-top">
                <td className="px-3 py-2">
                  <div className="font-medium text-gray-800 dark:text-gray-200">{s.display_name}</div>
                  {s.cooldown_until && (
                    <div className="text-xs text-amber-700">rate-limited until {s.cooldown_until.slice(0, 16).replace('T', ' ')}</div>
                  )}
                </td>
                <td className="px-3 py-2 text-xs">
                  {s.has_key ? (
                    <span className="text-green-700" title={s.key_fingerprint ?? ''}>
                      ••••{s.key_last4} <span className="text-gray-400">v{s.key_version}</span>
                    </span>
                  ) : (
                    <span className="text-gray-400">none</span>
                  )}
                </td>
                <td className="px-3 py-2">
                  <input type="checkbox" aria-label={`${s.source} enabled`} disabled={!isAdmin || !s.has_key}
                    checked={s.enabled} onChange={(e) => void save(s, { enabled: e.target.checked })} />
                </td>
                <td className="px-3 py-2">
                  <input type="number" aria-label={`${s.source} daily budget`} min={0} disabled={!isAdmin}
                    defaultValue={s.daily_budget}
                    onBlur={(e) => { const v = Number(e.target.value); if (v !== s.daily_budget) void save(s, { daily_budget: v }) }}
                    className="w-24 rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900 px-2 py-1" />
                  <div className="text-xs text-gray-400">default {s.daily_budget_default}</div>
                </td>
                <td className="px-3 py-2">
                  <input type="number" aria-label={`${s.source} cache ttl hours`} min={0} disabled={!isAdmin}
                    defaultValue={s.cache_ttl_hours}
                    onBlur={(e) => { const v = Number(e.target.value); if (v !== s.cache_ttl_hours) void save(s, { cache_ttl_hours: v }) }}
                    className="w-20 rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900 px-2 py-1" />
                  <div className="text-xs text-gray-400">default {s.cache_ttl_hours_default}</div>
                </td>
                <td className="px-3 py-2">
                  <input type="password" aria-label={`${s.source} key`} autoComplete="off" disabled={!isAdmin}
                    placeholder={s.has_key ? 'enter a new key to rotate' : 'paste API key'}
                    value={keyDraft[s.source] ?? ''} onChange={(e) => setKeyDraft({ ...keyDraft, [s.source]: e.target.value })}
                    className="w-56 rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900 px-2 py-1" />
                  {isAdmin && (
                    <button onClick={() => void save(s, {})} disabled={!(keyDraft[s.source]?.trim())}
                      className="ml-2 rounded bg-indigo-600 px-2 py-1 text-xs text-white hover:bg-indigo-700 disabled:opacity-40">
                      Save key
                    </button>
                  )}
                </td>
                <td className="px-3 py-2">
                  {isAdmin && s.has_key && (
                    <button onClick={() => void removeKey(s)}
                      className="rounded border border-red-300 px-2 py-1 text-xs text-red-700 hover:bg-red-50 dark:hover:bg-red-950">
                      Remove
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  )
}
