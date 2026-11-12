import { useEffect, useRef, useState } from 'react'
import cytoscape from 'cytoscape'
import type { EventObject } from 'cytoscape'
import { useAuth } from './AuthContext'
import * as api from './api'
import type { GraphData, GraphNode } from './api'

// Phase 7.6: interactive event-relationship graph (Cytoscape.js, MIT). Node types colour-coded;
// click a node to see its details. Text-only labels - never raw log rendering. analyst+ only.
export function GraphView({ kind, id }: { kind: 'incident' | 'campaign'; id: number }) {
  const { session } = useAuth()
  const canView = session?.role === 'admin' || session?.role === 'analyst'
  const [data, setData] = useState<GraphData | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [selected, setSelected] = useState<GraphNode | null>(null)
  const boxRef = useRef<HTMLDivElement>(null)

  async function load() {
    if (!session) return
    setBusy(true); setError(null)
    try {
      const fn = kind === 'incident' ? api.fetchIncidentGraph : api.fetchCampaignGraph
      setData(await fn(session.accessToken, id))
    } catch (e) {
      setError(e instanceof api.ApiError ? e.message : 'could not load graph')
    } finally {
      setBusy(false)
    }
  }

  useEffect(() => {
    if (!data || !boxRef.current) return
    const cy = cytoscape({
      container: boxRef.current,
      elements: [
        ...data.nodes.map((n) => ({ data: { id: n.id, label: n.label, colour: n.colour, type: n.type } })),
        ...data.edges.map((e) => ({ data: { source: e.source, target: e.target, label: `${e.relation}${e.count > 1 ? ` ×${e.count}` : ''}` } })),
      ],
      style: [
        { selector: 'node', style: { 'background-color': 'data(colour)', label: 'data(label)', 'font-size': 9,
          color: '#111', 'text-wrap': 'wrap', 'text-max-width': '120px', width: 18, height: 18 } },
        { selector: 'edge', style: { width: 1, 'line-color': '#cbd5e1', 'target-arrow-color': '#cbd5e1',
          'target-arrow-shape': 'triangle', 'curve-style': 'bezier', label: 'data(label)', 'font-size': 7, color: '#64748b' } },
      ],
      layout: { name: 'cose', animate: false, padding: 20 },
    })
    cy.on('tap', 'node', (ev: EventObject) => {
      const nid = ev.target.id()
      setSelected(data.nodes.find((n) => n.id === nid) ?? null)
    })
    return () => cy.destroy()
  }, [data])

  if (!canView) return null
  return (
    <section className="mt-6">
      <div className="mb-2 flex items-center gap-3">
        <h2 className="text-sm font-semibold text-gray-700 dark:text-gray-300">Relationship graph</h2>
        <button onClick={() => void load()} disabled={busy}
          className="rounded bg-indigo-600 px-2 py-1 text-xs text-white hover:bg-indigo-700 disabled:opacity-50">
          {busy ? 'Building…' : data ? 'Rebuild' : 'Build graph'}
        </button>
        {data && (
          <span className="text-xs text-gray-500">
            {data.summary.node_count} nodes · {data.summary.edge_count} edges · {data.response_ms} ms{data.cached ? ' (cached)' : ''}
            {data.summary.capped && <span className="ml-2 text-amber-700">{data.summary.notes.join('; ')}</span>}
          </span>
        )}
      </div>
      {error && <p className="text-sm text-amber-700">{error}</p>}
      {data && (
        <div className="flex gap-3">
          <div ref={boxRef} className="h-[460px] flex-1 rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900" />
          <div className="w-64 shrink-0 text-xs text-gray-600 dark:text-gray-300 space-y-2">
            {selected ? (
              <div className="rounded border border-gray-200 dark:border-gray-700 p-2">
                <div className="font-semibold">{selected.type}</div>
                <div className="break-all font-mono">{selected.label}</div>
                {selected.external && <div className="text-red-700">external IP</div>}
                {selected.kev && <div className="text-red-700">KEV (actively exploited)</div>}
                {selected.mitre && selected.mitre.length > 0 && <div>MITRE: {selected.mitre.join(', ')}</div>}
              </div>
            ) : <div className="text-gray-400">click a node for details</div>}
            <div className="rounded border border-gray-200 dark:border-gray-700 p-2 space-y-1">
              <div className="font-semibold">Analysis</div>
              <div>components: {data.analytics.components.join(', ') || '—'}</div>
              <div>central: {data.analytics.most_central_degree.slice(0, 3).join(', ') || '—'}</div>
              {data.analytics.external_ip_to_host_path && (
                <div className="text-red-700">attack path: {data.analytics.external_ip_to_host_path.join(' → ')}</div>
              )}
              {data.shared_nodes && data.shared_nodes.length > 0 && (
                <div>shared across incidents: {data.shared_nodes.slice(0, 3).map((s) => s[0]).join(', ')}</div>
              )}
              {data.campaign_actor && <div>campaign actor: {data.campaign_actor}</div>}
            </div>
            <div className="flex flex-wrap gap-2">
              {Object.entries({ host: '#2563eb', user: '#7c3aed', ip: '#dc2626', rule: '#64748b', file: '#ea580c', ioc: '#be123c', cve: '#b45309', yara: '#c026d3' }).map(([t, c]) => (
                <span key={t} className="flex items-center gap-1"><span className="inline-block h-2 w-2 rounded-full" style={{ background: c }} />{t}</span>
              ))}
            </div>
          </div>
        </div>
      )}
    </section>
  )
}
