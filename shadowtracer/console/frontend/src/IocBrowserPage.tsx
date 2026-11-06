import { useEffect, useState } from 'react'
import { useAuth } from './AuthContext'
import * as api from './api'
import type { Ioc, IocQuery } from './api'

// Phase 6.4: the tenant's view of the IOC store - global intel and its own private IOCs,
// never another tenant's (enforced by the API). Feed values render as plain text.
const TYPES = ['', 'ipv4', 'ipv6', 'cidr4', 'cidr6', 'domain', 'url', 'md5', 'sha1', 'sha256']
const PAGE = 50

export function IocBrowserPage() {
  const { session } = useAuth()
  const [query, setQuery] = useState<IocQuery>({ scope: 'all', expiry: 'live', min_confidence: 0 })
  const [draft, setDraft] = useState<IocQuery>(query)
  const [offset, setOffset] = useState(0)
  const [result, setResult] = useState<{ total: number; iocs: Ioc[] } | null>(null)
  const [sources, setSources] = useState<string[]>([])
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!session) return
    api.fetchTiOverview(session.accessToken).then((o) => setSources(o.sources.map((s) => s.name))).catch(() => setSources([]))
  }, [session])

  useEffect(() => {
    if (!session) return
    api.fetchIocs(session.accessToken, { ...query, limit: PAGE, offset })
      .then((r) => { setResult(r); setError(null) })
      .catch(() => setError('Could not load IOCs.'))
  }, [session, query, offset])

  const field = 'rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900 px-2 py-1.5 text-sm'
  return (
    <div className="p-6">
      <h1 className="mb-4 text-lg font-semibold text-gray-900 dark:text-gray-100">Threat intel - IOC browser</h1>
      <form
        className="mb-4 flex flex-wrap items-end gap-2"
        onSubmit={(e) => { e.preventDefault(); setOffset(0); setQuery(draft) }}
      >
        <input aria-label="search" placeholder="Search value…" value={draft.q ?? ''} onChange={(e) => setDraft({ ...draft, q: e.target.value })} className={`${field} min-w-[14rem]`} />
        <select aria-label="type" value={draft.type ?? ''} onChange={(e) => setDraft({ ...draft, type: e.target.value || undefined })} className={field}>
          {TYPES.map((t) => <option key={t} value={t}>{t || 'any type'}</option>)}
        </select>
        <select aria-label="source" value={draft.source ?? ''} onChange={(e) => setDraft({ ...draft, source: e.target.value || undefined })} className={field}>
          <option value="">any source</option>
          {sources.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <select aria-label="scope" value={draft.scope} onChange={(e) => setDraft({ ...draft, scope: e.target.value as IocQuery['scope'] })} className={field}>
          <option value="all">global + this tenant</option>
          <option value="global">global only</option>
          <option value="tenant">this tenant only</option>
        </select>
        <label className="text-xs text-gray-500">
          min confidence
          <input aria-label="min confidence" type="number" min={0} max={100} value={draft.min_confidence ?? 0}
            onChange={(e) => setDraft({ ...draft, min_confidence: Number(e.target.value) })} className={`${field} ml-1 w-20`} />
        </label>
        <select aria-label="expiry" value={draft.expiry} onChange={(e) => setDraft({ ...draft, expiry: e.target.value as IocQuery['expiry'] })} className={field}>
          <option value="live">not expired</option>
          <option value="expired">expired</option>
          <option value="all">any expiry</option>
        </select>
        <button type="submit" className="rounded bg-indigo-600 px-3 py-1.5 text-sm text-white hover:bg-indigo-700">Search</button>
      </form>
      {error && <p className="text-sm text-red-600">{error}</p>}
      {result && (
        <>
          <p className="mb-2 text-sm text-gray-500">{result.total.toLocaleString()} IOCs</p>
          <div className="overflow-hidden rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800">
            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700 text-sm">
              <thead className="bg-gray-50 dark:bg-gray-900">
                <tr>
                  {['Value', 'Type', 'Scope', 'Sources', 'Confidence', 'TLP', 'Tags', 'Last seen', 'Expires'].map((h) => (
                    <th key={h} className="px-3 py-2 text-left text-xs font-medium text-gray-500">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {result.iocs.map((i) => (
                  <tr key={i.id} className="border-b border-gray-200 dark:border-gray-700 align-top">
                    <td className="px-3 py-2 break-all font-mono text-xs">{i.value}</td>
                    <td className="px-3 py-2 text-xs">{i.type}</td>
                    <td className="px-3 py-2 text-xs">{i.scope}</td>
                    <td className="px-3 py-2 text-xs">{i.sources.join(', ')}</td>
                    <td className="px-3 py-2 text-xs">{i.confidence}</td>
                    <td className="px-3 py-2 text-xs uppercase">{i.tlp}</td>
                    <td className="px-3 py-2 text-xs text-gray-600 dark:text-gray-300">{i.labels.slice(0, 4).join(', ')}</td>
                    <td className="px-3 py-2 whitespace-nowrap text-xs text-gray-500">{i.last_seen.slice(0, 10)}</td>
                    <td className="px-3 py-2 whitespace-nowrap text-xs text-gray-500">{i.expires_at.slice(0, 10)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="mt-3 flex gap-2 text-sm">
            <button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))} className="rounded bg-gray-100 dark:bg-gray-700 px-3 py-1 disabled:opacity-40">Previous</button>
            <button disabled={offset + PAGE >= result.total} onClick={() => setOffset(offset + PAGE)} className="rounded bg-gray-100 dark:bg-gray-700 px-3 py-1 disabled:opacity-40">Next</button>
          </div>
        </>
      )}
    </div>
  )
}
