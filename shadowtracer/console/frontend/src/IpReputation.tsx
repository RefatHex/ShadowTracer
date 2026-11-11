import { useState } from 'react'
import { useAuth } from './AuthContext'
import * as api from './api'
import type { IpVerdict } from './api'

// Phase 6.5 C: on-demand IP reputation for one source IP. analyst+ clicks a source; the backend
// spends that tenant's own key once (budget/cache/audit) and returns a verdict. Nothing is called
// automatically. Viewers see the IP but no buttons (the API would 403 anyway).
const STATUS_STYLE: Record<string, string> = {
  malicious: 'text-red-700', suspicious: 'text-amber-700', clean: 'text-green-700', unknown: 'text-gray-500',
}

export function IpReputation({ ip }: { ip: string }) {
  const { session } = useAuth()
  const canLookup = session?.role === 'admin' || session?.role === 'analyst'
  const [verdicts, setVerdicts] = useState<Record<string, IpVerdict>>({})
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  async function run(source: 'abuseipdb' | 'greynoise') {
    if (!session) return
    setBusy(source); setError(null)
    try {
      const v = await api.lookupIp(session.accessToken, ip, source)
      setVerdicts((prev) => ({ ...prev, [source]: v }))
    } catch (e) {
      if (e instanceof api.ApiError) {
        setError(e.status === 409 ? `${source} not enabled` : e.status === 429 ? `${source}: rate/budget limit`
          : e.status === 503 ? 'key management not configured' : `${source}: ${e.message}`)
      } else setError('lookup failed')
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className="flex flex-wrap items-center gap-2">
      <span className="font-mono text-xs">{ip}</span>
      {canLookup && (['abuseipdb', 'greynoise'] as const).map((s) => (
        <button key={s} onClick={() => void run(s)} disabled={busy === s}
          className="rounded border border-gray-300 dark:border-gray-600 px-1.5 py-0.5 text-xs text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 disabled:opacity-50">
          {busy === s ? '…' : s === 'abuseipdb' ? 'AbuseIPDB' : 'GreyNoise'}
        </button>
      ))}
      {Object.entries(verdicts).map(([s, v]) => (
        <span key={s} className={`text-xs ${STATUS_STYLE[v.status] ?? 'text-gray-500'}`}>
          {s === 'abuseipdb' ? 'AbuseIPDB' : 'GreyNoise'}: {v.status}
          {v.served_from === 'cache' && <span className="text-gray-400"> (cached)</span>}
        </span>
      ))}
      {error && <span className="text-xs text-amber-700">{error}</span>}
    </div>
  )
}
