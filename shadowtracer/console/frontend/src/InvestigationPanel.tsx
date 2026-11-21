import { useEffect, useState } from 'react'
import { useAuth } from './AuthContext'
import * as api from './api'
import type { Investigation } from './api'

// Phase 7.7: analyst-triggered LLM investigation. Read-only, advisory, AI-generated. The summary is
// built only from evidence the console gathered; every cited id links to its evidence, and sentences
// the verify step could not back are shown as "unverified". analyst+ only.
const SECTIONS = ['SUMMARY', 'TIMELINE', 'TECHNIQUES', 'NEXT_STEPS', 'CONFIDENCE'] as const

function scrollToEvidence(id: string) {
  const el = document.getElementById(`evidence-${id}`)
  if (el) { el.scrollIntoView({ behavior: 'smooth', block: 'center' }); el.classList.add('ring-2', 'ring-indigo-400'); setTimeout(() => el.classList.remove('ring-2', 'ring-indigo-400'), 1500) }
}

// Render a section's text, turning [E1] / [E1, E3] citations into clickable chips.
function Cited({ text }: { text: string }) {
  const parts = text.split(/(\[[^\]]*?E\d+[^\]]*?\])/g)
  return (
    <>
      {parts.map((p, i) => {
        const m = p.match(/^\[(.*?)\]$/)
        if (m && /E\d+/.test(m[1])) {
          const ids = m[1].match(/E\d+/g) || []
          return (
            <span key={i}>
              [{ids.map((id, j) => (
                <button key={id} onClick={() => scrollToEvidence(id)}
                  className="font-mono text-indigo-600 hover:underline dark:text-indigo-400">{j ? ', ' : ''}{id}</button>
              ))}]
            </span>
          )
        }
        return <span key={i}>{p}</span>
      })}
    </>
  )
}

export function InvestigationPanel({ incidentId }: { incidentId: number }) {
  const { session } = useAuth()
  const canUse = session?.role === 'admin' || session?.role === 'analyst'
  const [inv, setInv] = useState<Investigation | null | undefined>(undefined)
  const [running, setRunning] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!session || !canUse) return
    api.fetchInvestigation(session.accessToken, incidentId).then(setInv).catch(() => setInv(null))
  }, [session, incidentId, canUse])

  if (!canUse) return null

  async function run() {
    if (!session) return
    setRunning(true); setError(null)
    try {
      await api.runInvestigation(session.accessToken, incidentId)   // queues; returns {status:'running'}
      // poll the background job until it reaches a terminal status
      const deadline = Date.now() + 4 * 60 * 1000
      while (Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 2000))
        const latest = await api.fetchInvestigation(session.accessToken, incidentId)
        if (latest) setInv(latest)
        if (latest && latest.status !== 'running') return
      }
      setError('Investigation is taking longer than expected; check back shortly.')
    } catch (e) {
      setError((e as Error).message || 'Investigation failed.')
    } finally {
      setRunning(false)
    }
  }

  const unverified = inv?.sentences?.filter((s) => !s.verified) ?? []

  return (
    <section className="mt-6">
      <div className="mb-2 flex items-center gap-2">
        <h2 className="text-sm font-semibold text-gray-700 dark:text-gray-300">AI investigation</h2>
        <span className="rounded bg-amber-100 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-amber-700 dark:bg-amber-950 dark:text-amber-300">AI-generated, check the evidence</span>
        <button onClick={run} disabled={running}
          className="ml-auto rounded bg-indigo-600 px-3 py-1 text-sm font-medium text-white hover:bg-indigo-500 disabled:opacity-50">
          {running ? 'Investigating…' : inv ? 'Re-investigate' : 'Investigate'}
        </button>
      </div>

      {error && <p className="text-sm text-amber-700">{error}</p>}
      {inv === undefined && <p className="text-sm text-gray-400">Loading…</p>}
      {inv === null && !running && <p className="text-sm text-gray-400">No investigation yet. Click Investigate to generate one.</p>}

      {inv && inv.status !== 'ok' && inv.status !== 'running' && (
        <p className="mb-3 rounded bg-amber-50 p-2 text-sm text-amber-800 dark:bg-amber-950 dark:text-amber-300">
          {inv.message || 'The investigation could not be completed.'} The evidence pack is shown below.
        </p>
      )}

      {inv && inv.status === 'ok' && inv.sections && (
        <div className="rounded-lg border border-gray-200 bg-white p-4 dark:border-gray-700 dark:bg-gray-800">
          {SECTIONS.filter((k) => inv.sections?.[k]?.trim()).map((k) => (
            <div key={k} className="mb-2">
              <span className="text-[11px] font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400">{k.replace('_', ' ')}</span>
              <p className="text-sm text-gray-800 dark:text-gray-200"><Cited text={inv.sections![k]} /></p>
            </div>
          ))}
          <p className="mt-2 text-xs text-gray-400">
            {inv.model} · {inv.prompt_version} · {inv.latency_ms} ms · {inv.tokens} tokens
            {unverified.length > 0 && <span className="ml-2 text-amber-600">· {unverified.length} unverified sentence(s)</span>}
          </p>
        </div>
      )}

      {unverified.length > 0 && inv?.status === 'ok' && (
        <div className="mt-2 rounded border border-amber-300 bg-amber-50 p-2 dark:border-amber-800 dark:bg-amber-950">
          <p className="text-[11px] font-semibold uppercase tracking-wide text-amber-700 dark:text-amber-300">Unverified — not backed by the cited evidence</p>
          {unverified.map((s, i) => (
            <p key={i} className="text-sm text-amber-800 dark:text-amber-300">“{s.text}” <span className="text-xs">(missing: {s.unsupported.join(', ') || 'no citation'})</span></p>
          ))}
        </div>
      )}

      {inv?.evidence && inv.evidence.length > 0 && (
        <div className="mt-3">
          <p className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400">Evidence</p>
          <ul className="space-y-1">
            {inv.evidence.map((e) => (
              <li key={e.id} id={`evidence-${e.id}`} className="rounded bg-gray-50 p-2 text-sm dark:bg-gray-900">
                <span className="font-mono text-indigo-600 dark:text-indigo-400">{e.id}</span>{' '}
                <span className="font-medium text-gray-700 dark:text-gray-300">{e.title}:</span>{' '}
                <span className="whitespace-pre-wrap text-gray-600 dark:text-gray-400">{e.body}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  )
}
