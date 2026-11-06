import { useState } from 'react'
import { useAuth } from './AuthContext'
import * as api from './api'
import type { TiMatch, TiVerdict } from './api'

// Phase 6.4: threat-intel matches on an incident. Every value comes from a feed or an alert
// and is rendered as plain JSX text; a source link is an <a> only when safeHttpUrl() accepts
// it (http/https), never javascript:/data:.

function Verdict({ v }: { v: TiVerdict }) {
  const link = api.safeHttpUrl(v.permalink)
  return (
    <span className={v.status === 'malicious' ? 'text-red-700 dark:text-red-400' : 'text-gray-600'}>
      VirusTotal: {v.status} {v.malicious}/{v.total}
      {v.labels.length > 0 && ` · ${v.labels.slice(0, 3).join(', ')}`}
      {v.last_analysis && ` · analysed ${v.last_analysis.slice(0, 10)}`}
      {link && (
        <>
          {' · '}
          <a href={link} target="_blank" rel="noopener noreferrer" className="text-indigo-600 hover:underline">
            report
          </a>
        </>
      )}
    </span>
  )
}

export function TiSection({ matches, onChanged }: { matches: TiMatch[]; onChanged: () => void }) {
  const { session } = useAuth()
  const canAct = session?.role === 'admin' || session?.role === 'analyst'
  const [message, setMessage] = useState<string | null>(null)
  const [lookups, setLookups] = useState<Record<string, TiVerdict | string>>({})

  async function checkVirusTotal(sha256: string) {
    if (!session) return
    try {
      const r = await api.vtLookup(session.accessToken, sha256)
      setLookups((l) => ({
        ...l,
        [sha256]: r.status === 'cached' && r.verdict ? r.verdict
          : r.status === 'budget_reached' ? 'Daily VirusTotal budget reached - queued for later'
          : 'Queued for VirusTotal',
      }))
    } catch (e) {
      setLookups((l) => ({ ...l, [sha256]: e instanceof api.ApiError ? e.message : 'VirusTotal check failed' }))
    }
  }

  async function markFalsePositive(m: TiMatch) {
    if (!session) return
    const reason = window.prompt(`Why is ${m.observable} a false positive for this tenant?`)
    if (!reason || reason.trim().length < 3) return
    try {
      await api.markFalsePositive(session.accessToken, m.id, reason.trim())
      setMessage(`${m.observable} is now allowlisted for this tenant; it will not match again.`)
      onChanged()
    } catch {
      setMessage('Could not mark the hit as a false positive.')
    }
  }

  if (matches.length === 0) return null
  return (
    <section className="mb-6">
      <h2 className="mb-2 text-sm font-semibold text-gray-700 dark:text-gray-300">Threat intel ({matches.length})</h2>
      {message && <p className="mb-2 text-sm text-gray-500">{message}</p>}
      <div className="overflow-hidden rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800">
        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700 text-sm">
          <thead className="bg-gray-50 dark:bg-gray-900">
            <tr>
              {['Observable', 'IOC', 'Sources', 'Confidence', 'TLP', 'Tags / MITRE', 'First seen', ''].map((h) => (
                <th key={h} className="px-3 py-2 text-left text-xs font-medium text-gray-500">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {matches.map((m) => {
              const lookup = lookups[m.observable]
              return (
                <tr key={m.id} className="border-b border-gray-200 dark:border-gray-700 align-top">
                  <td className="px-3 py-2">
                    <div className="break-all font-mono text-xs">{m.observable}</div>
                    <div className="text-xs text-gray-500">{m.field} · alert {m.alert_id}{m.origin === 'retro' && ' · retro-hunt'}</div>
                  </td>
                  <td className="px-3 py-2">
                    <div className="text-xs">{m.ioc_type}</div>
                    {m.ioc_value !== m.observable && <div className="break-all font-mono text-xs text-gray-500">{m.ioc_value}</div>}
                  </td>
                  <td className="px-3 py-2 text-xs">
                    {m.source_details.map((s) => {
                      const link = api.safeHttpUrl(s.reference_url)
                      return (
                        <div key={s.name}>
                          {link ? (
                            <a href={link} target="_blank" rel="noopener noreferrer" className="text-indigo-600 hover:underline">{s.name}</a>
                          ) : s.name}
                          {s.source_info && <span className="text-gray-500"> · {s.source_info}</span>}
                        </div>
                      )
                    })}
                    {m.source_details.length === 0 && m.sources.join(', ')}
                  </td>
                  <td className="px-3 py-2 text-xs">{m.confidence}</td>
                  <td className="px-3 py-2 text-xs uppercase">{m.tlp}</td>
                  <td className="px-3 py-2 text-xs text-gray-600 dark:text-gray-300">
                    {m.labels.slice(0, 5).join(', ') || '—'}
                    {m.mitre.length > 0 && <div className="text-gray-500">{m.mitre.join(', ')}</div>}
                  </td>
                  <td className="px-3 py-2 whitespace-nowrap text-xs text-gray-500">{m.first_seen.slice(0, 10)}</td>
                  <td className="px-3 py-2 text-xs">
                    {m.virustotal && <div className="mb-1"><Verdict v={m.virustotal} /></div>}
                    {typeof lookup === 'object' && <div className="mb-1"><Verdict v={lookup} /></div>}
                    {typeof lookup === 'string' && <div className="mb-1 text-amber-700">{lookup}</div>}
                    {canAct && m.observable_type === 'sha256' && (
                      <button onClick={() => void checkVirusTotal(m.observable)} className="mr-2 rounded bg-gray-100 dark:bg-gray-700 px-2 py-1 hover:bg-gray-200">
                        Check on VirusTotal
                      </button>
                    )}
                    {m.false_positive ? (
                      <span className="text-gray-500">false positive</span>
                    ) : canAct && (
                      <button onClick={() => void markFalsePositive(m)} className="rounded bg-gray-100 dark:bg-gray-700 px-2 py-1 hover:bg-gray-200">
                        Mark false positive
                      </button>
                    )}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </section>
  )
}
