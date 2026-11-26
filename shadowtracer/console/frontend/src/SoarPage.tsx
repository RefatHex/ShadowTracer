import { useCallback, useEffect, useState } from 'react'
import { useAuth } from './AuthContext'
import * as api from './api'

type Tab = 'approvals' | 'history' | 'playbooks' | 'assets' | 'settings'
const MODE_COLORS: Record<string, string> = {
  shadow: 'bg-gray-100 text-gray-700', approval: 'bg-amber-100 text-amber-800', auto: 'bg-green-100 text-green-800',
}
const STATUS_COLORS: Record<string, string> = {
  shadow: 'text-gray-500', requested: 'text-amber-600', approved: 'text-blue-600', executed: 'text-green-600',
  undone: 'text-gray-600', expired: 'text-gray-500', refused: 'text-red-600', failed: 'text-red-700',
}
const pct = (v: number | null) => (v == null ? '—' : `${(v * 100).toFixed(1)}%`)
const secs = (v: number | null) => (v == null ? '—' : v >= 3600 ? `${(v / 3600).toFixed(1)}h` : v >= 60 ? `${(v / 60).toFixed(0)}m` : `${v.toFixed(0)}s`)

function countdown(expires: string | null): string {
  if (!expires) return '—'
  const ms = new Date(expires).getTime() - Date.now()
  if (ms <= 0) return 'expired'
  const m = Math.floor(ms / 60000)
  return m >= 60 ? `${Math.floor(m / 60)}h ${m % 60}m` : `${m}m`
}

function Badge({ text, cls }: { text: string; cls: string }) {
  return <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${cls}`}>{text}</span>
}

function Metrics({ token }: { token: string }) {
  const [m, setM] = useState<api.SoarMetrics | null>(null)
  useEffect(() => { api.fetchSoarMetrics(token).then(setM).catch(() => setM(null)) }, [token])
  if (!m) return null
  const cell = (label: string, val: string) => (
    <div className="rounded border border-gray-200 dark:border-gray-700 px-3 py-2">
      <div className="text-xs text-gray-500">{label}</div><div className="text-lg font-semibold">{val}</div>
    </div>
  )
  return (
    <div className="mb-4 grid grid-cols-2 gap-2 sm:grid-cols-6">
      {cell('MTTD', secs(m.mttd_seconds))}{cell('MTTC', secs(m.mttc_seconds))}
      {cell('Automation', pct(m.automation_rate))}{cell('Undo rate', pct(m.undo_rate))}
      {cell('FP actions', pct(m.false_positive_action_rate))}{cell('Executions', String(m.executions))}
    </div>
  )
}

function ReasonRow({ onApprove, onDeny }: { onApprove: (r: string) => void; onDeny: (r: string) => void }) {
  const [reason, setReason] = useState('')
  return (
    <div className="flex items-center gap-2">
      <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="reason (required)"
        className="rounded border border-gray-300 px-2 py-1 text-sm" />
      <button onClick={() => onApprove(reason)} className="rounded bg-green-600 px-2 py-1 text-xs text-white hover:bg-green-700">Approve</button>
      <button onClick={() => onDeny(reason)} className="rounded bg-red-600 px-2 py-1 text-xs text-white hover:bg-red-700">Deny</button>
    </div>
  )
}

function Approvals({ token }: { token: string }) {
  const [rows, setRows] = useState<api.SoarAction[]>([])
  const [err, setErr] = useState<string | null>(null)
  const load = useCallback(() => { api.fetchSoarApprovals(token).then((r) => setRows(r.pending)).catch(() => {}) }, [token])
  useEffect(load, [load])
  const act = async (fn: Promise<unknown>) => {
    setErr(null)
    try { await fn; load() } catch (e) { setErr(e instanceof api.ApiError ? e.message : 'failed') }
  }
  if (!rows.length) return <p className="text-sm text-gray-500">No approvals pending.</p>
  return (
    <div className="space-y-2">
      {err && <p className="rounded bg-red-50 px-3 py-2 text-sm text-red-700">{err}</p>}
      {rows.map((a) => (
        <div key={a.id} className="rounded border border-gray-200 dark:border-gray-700 p-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="text-sm">
              <Badge text={a.action_type} cls="bg-indigo-100 text-indigo-800" /> <span className="font-mono">{a.target}</span>
              {' '}on agent {a.agent_id} · incident #{a.incident_id} · block {secs(a.block_seconds)}
            </div>
            <ReasonRow onApprove={(r) => act(api.approveAction(token, a.id, r))} onDeny={(r) => act(api.denyAction(token, a.id, r))} />
          </div>
          <div className="mt-1 text-xs text-gray-500">signals: {a.signals.map((s) => s.type).join(', ') || '—'} · playbook {a.playbook_key}</div>
        </div>
      ))}
    </div>
  )
}

function History({ token }: { token: string }) {
  const [rows, setRows] = useState<api.SoarAction[]>([])
  const [filter, setFilter] = useState('')
  const load = useCallback(() => { api.fetchSoarActions(token).then((r) => setRows(r.actions)).catch(() => {}) }, [token])
  useEffect(load, [load])
  const shown = filter ? rows.filter((r) => r.status === filter) : rows
  return (
    <div>
      <div className="mb-2 flex gap-2 text-xs">
        <button onClick={() => setFilter('')} className={`rounded px-2 py-1 ${!filter ? 'bg-indigo-600 text-white' : 'bg-gray-100'}`}>all</button>
        {['executed', 'requested', 'refused', 'expired', 'undone', 'shadow'].map((s) => (
          <button key={s} onClick={() => setFilter(s)} className={`rounded px-2 py-1 ${filter === s ? 'bg-indigo-600 text-white' : 'bg-gray-100'}`}>{s}</button>
        ))}
      </div>
      <table className="w-full text-sm">
        <thead><tr className="text-left text-xs text-gray-500"><th className="py-1">Action</th><th>Target</th><th>Status</th><th>Expires</th><th>Incident</th><th></th></tr></thead>
        <tbody>
          {shown.map((a) => (
            <tr key={a.id} className="border-t border-gray-100 dark:border-gray-700">
              <td className="py-1">{a.action_type}</td>
              <td className="font-mono">{a.target}</td>
              <td className={STATUS_COLORS[a.status] || ''}>{a.status}{a.refuse_reason ? ` (${a.refuse_reason})` : ''}</td>
              <td className="text-xs">{a.status === 'executed' ? countdown(a.block_expires_at) : '—'}</td>
              <td>#{a.incident_id}</td>
              <td>{a.status === 'executed' && a.action_type !== 'collect_evidence' && (
                <button onClick={() => api.undoAction(token, a.id).then(load).catch(() => {})}
                  className="rounded bg-gray-200 px-2 py-0.5 text-xs hover:bg-gray-300">Undo</button>
              )}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function Playbooks({ token, isAdmin }: { token: string; isAdmin: boolean }) {
  const [rows, setRows] = useState<api.SoarPlaybook[]>([])
  const [err, setErr] = useState<string | null>(null)
  const load = useCallback(() => { api.fetchSoarPlaybooks(token).then((r) => setRows(r.playbooks)).catch(() => {}) }, [token])
  useEffect(load, [load])
  const change = async (key: string, mode: string) => {
    setErr(null)
    try { await api.setPlaybookMode(token, key, mode); load() } catch (e) { setErr(e instanceof api.ApiError ? e.message : 'failed') }
  }
  return (
    <div>
      {err && <p className="mb-2 rounded bg-red-50 px-3 py-2 text-sm text-red-700">{err}</p>}
      <table className="w-full text-sm">
        <thead><tr className="text-left text-xs text-gray-500"><th className="py-1">Playbook</th><th>Mode</th><th>v</th><th>Shadow precision</th><th>Verdicts</th><th>Block</th><th>Promote</th></tr></thead>
        <tbody>
          {rows.map((p) => (
            <tr key={p.playbook_key} className="border-t border-gray-100 dark:border-gray-700 align-top">
              <td className="py-1">{p.title}<div className="text-xs text-gray-400 font-mono">{p.playbook_key}</div></td>
              <td><Badge text={p.mode} cls={MODE_COLORS[p.mode] || ''} /></td>
              <td>{p.version}</td>
              <td>{pct(p.precision)} <span className="text-xs text-gray-400">(≥{pct(p.min_precision)})</span></td>
              <td>{p.verdict_count} <span className="text-xs text-gray-400">/{p.min_incidents}</span></td>
              <td>{secs(p.block_seconds)}</td>
              <td>{isAdmin ? (
                <div className="flex flex-col gap-1">
                  {p.mode !== 'auto' && (
                    <button disabled={!p.can_promote_to_auto} onClick={() => change(p.playbook_key, 'auto')}
                      title={p.promote_blocked_reason || ''}
                      className={`rounded px-2 py-0.5 text-xs text-white ${p.can_promote_to_auto ? 'bg-green-600 hover:bg-green-700' : 'bg-gray-300 cursor-not-allowed'}`}>
                      Promote to auto
                    </button>
                  )}
                  {!p.can_promote_to_auto && p.mode !== 'auto' && <span className="text-xs text-gray-400">{p.promote_blocked_reason}</span>}
                  {p.mode !== 'shadow' && <button onClick={() => change(p.playbook_key, 'shadow')} className="rounded bg-gray-200 px-2 py-0.5 text-xs">→ shadow</button>}
                  {p.mode !== 'approval' && <button onClick={() => change(p.playbook_key, 'approval')} className="rounded bg-gray-200 px-2 py-0.5 text-xs">→ approval</button>}
                </div>
              ) : <span className="text-xs text-gray-400">admin only</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function AssetLevels({ token }: { token: string }) {
  const [rows, setRows] = useState<api.AssetLevelRow[]>([])
  const [def, setDef] = useState('approval')
  const [form, setForm] = useState<api.AssetLevelRow>({ scope_type: 'agent', scope_value: '', level: 'none' })
  const load = useCallback(() => { api.fetchAssetLevels(token).then((r) => { setRows(r.levels); setDef(r.default) }).catch(() => {}) }, [token])
  useEffect(load, [load])
  const save = async () => { if (form.scope_value) { await api.setAssetLevel(token, form); setForm({ ...form, scope_value: '' }); load() } }
  return (
    <div className="space-y-3">
      <p className="text-sm text-gray-500">Default for every agent: <b>{def}</b>. Containment never touches a <b>none</b> asset.</p>
      <div className="flex flex-wrap items-end gap-2">
        <select value={form.scope_type} onChange={(e) => setForm({ ...form, scope_type: e.target.value })} className="rounded border px-2 py-1 text-sm">
          <option value="agent">agent</option><option value="role_tag">role_tag</option>
        </select>
        <input value={form.scope_value} onChange={(e) => setForm({ ...form, scope_value: e.target.value })} placeholder="agent id or role tag" className="rounded border px-2 py-1 text-sm" />
        <select value={form.level} onChange={(e) => setForm({ ...form, level: e.target.value })} className="rounded border px-2 py-1 text-sm">
          <option value="full">full</option><option value="approval">approval</option><option value="none">none</option>
        </select>
        <button onClick={save} className="rounded bg-indigo-600 px-3 py-1 text-sm text-white hover:bg-indigo-700">Set</button>
      </div>
      <table className="w-full text-sm">
        <thead><tr className="text-left text-xs text-gray-500"><th className="py-1">Scope</th><th>Value</th><th>Level</th></tr></thead>
        <tbody>{rows.map((r) => (
          <tr key={`${r.scope_type}:${r.scope_value}`} className="border-t border-gray-100 dark:border-gray-700">
            <td className="py-1">{r.scope_type}</td><td className="font-mono">{r.scope_value}</td>
            <td><Badge text={r.level} cls={r.level === 'none' ? 'bg-red-100 text-red-700' : r.level === 'full' ? 'bg-green-100 text-green-800' : 'bg-amber-100 text-amber-800'} /></td>
          </tr>
        ))}</tbody>
      </table>
    </div>
  )
}

function Settings({ token }: { token: string }) {
  const [s, setS] = useState<api.SoarSettings | null>(null)
  const [channels, setChannels] = useState<api.SoarChannel[]>([])
  const [msg, setMsg] = useState<string | null>(null)
  const [cidr, setCidr] = useState('')
  const load = useCallback(() => {
    api.fetchSoarSettings(token).then(setS).catch(() => {})
    api.fetchSoarChannels(token).then((r) => setChannels(r.channels)).catch(() => {})
  }, [token])
  useEffect(load, [load])
  const st = (s?.settings || {}) as Record<string, unknown>
  const toggleKill = async () => { await api.setKillSwitch(token, !st.kill_switch); load() }
  const addCidr = async () => { if (cidr) { await api.addAllowlist(token, cidr, ''); setCidr(''); load() } }
  const toggleChannel = async (c: api.SoarChannel) => { await api.setSoarChannel(token, c.channel, { enabled: !c.enabled }); load() }
  const test = async (c: string) => { const r = await api.testSoarChannel(token, c); setMsg(`queued ${r.queued} test message(s) to ${c}`) }
  return (
    <div className="space-y-5">
      {msg && <p className="rounded bg-blue-50 px-3 py-2 text-sm text-blue-700">{msg}</p>}
      <section>
        <h3 className="mb-1 font-medium">Kill switch</h3>
        <button onClick={toggleKill} className={`rounded px-3 py-1 text-sm text-white ${st.kill_switch ? 'bg-red-600' : 'bg-gray-500'}`}>
          Tenant containment: {st.kill_switch ? 'STOPPED (click to resume)' : 'active (click to stop)'}
        </button>
        {s?.global_kill_switch && <p className="mt-1 text-xs text-red-600">Global kill switch is ON (set by an operator).</p>}
        {st.circuit_breaker_tripped ? (
          <button onClick={() => api.updateSoarSettings(token, { circuit_breaker_tripped: false }).then(load)}
            className="ml-2 rounded bg-amber-600 px-3 py-1 text-sm text-white">Reset circuit breaker ({String(st.circuit_breaker_reason)})</button>
        ) : null}
      </section>
      <section>
        <h3 className="mb-1 font-medium">Limits & escalation</h3>
        <div className="text-sm text-gray-600 grid grid-cols-2 gap-1 sm:grid-cols-3">
          <span>Block default: {secs(Number(st.block_default_seconds))}</span>
          <span>Block max: {secs(Number(st.block_max_seconds))}</span>
          <span>Rate/hour: {String(st.rate_limit_per_hour)}</span>
          <span>Scope/run: {String(st.scope_limit_per_run)}</span>
          <span>Approval TTL: {secs(Number(st.approval_ttl_seconds))}</span>
          <span>Escalation: {Array.isArray(st.escalation_schedule) ? (st.escalation_schedule as number[]).map((x) => secs(x)).join(' → ') : '—'}</span>
        </div>
      </section>
      <section>
        <h3 className="mb-1 font-medium">Allowlist (never blocked)</h3>
        <div className="mb-2 flex gap-2">
          <input value={cidr} onChange={(e) => setCidr(e.target.value)} placeholder="10.0.0.0/8" className="rounded border px-2 py-1 text-sm font-mono" />
          <button onClick={addCidr} className="rounded bg-indigo-600 px-3 py-1 text-sm text-white">Add</button>
        </div>
        <ul className="text-sm">{(s?.allowlist || []).map((a) => (
          <li key={a.id} className="flex items-center gap-2 py-0.5"><span className="font-mono">{a.cidr}</span>
            <button onClick={() => api.delAllowlist(token, a.id).then(load)} className="text-xs text-red-600">remove</button></li>
        ))}<li className="text-xs text-gray-400">RFC1918, loopback, agent & manager IPs are always allowlisted automatically.</li></ul>
      </section>
      <section>
        <h3 className="mb-1 font-medium">Notification channels</h3>
        <table className="w-full text-sm">
          <thead><tr className="text-left text-xs text-gray-500"><th className="py-1">Channel</th><th>Configured</th><th>Enabled</th><th>Detail</th><th></th></tr></thead>
          <tbody>{channels.map((c) => (
            <tr key={c.channel} className="border-t border-gray-100 dark:border-gray-700">
              <td className="py-1">{c.channel}</td>
              <td>{c.configured ? <Badge text="configured" cls="bg-green-100 text-green-800" /> : <Badge text="not configured" cls="bg-gray-100 text-gray-500" />}</td>
              <td><input type="checkbox" checked={c.enabled} disabled={!c.configured} onChange={() => toggleChannel(c)} /></td>
              <td>
                <select value={c.detail_level} disabled={!c.configured} onChange={(e) => api.setSoarChannel(token, c.channel, { detail_level: e.target.value }).then(load)} className="rounded border px-1 py-0.5 text-xs">
                  <option value="minimal">minimal</option><option value="standard">standard</option>
                </select>
              </td>
              <td><button disabled={!c.configured} onClick={() => test(c.channel)} className="rounded bg-gray-200 px-2 py-0.5 text-xs disabled:opacity-40">Send test</button></td>
            </tr>
          ))}</tbody>
        </table>
      </section>
    </div>
  )
}

export function SoarPage() {
  const { session } = useAuth()
  const isAdmin = session?.role === 'admin'
  const [tab, setTab] = useState<Tab>('approvals')
  if (!session) return null
  const token = session.accessToken
  const tabs: { id: Tab; label: string; adminOnly?: boolean }[] = [
    { id: 'approvals', label: 'Approvals' }, { id: 'history', label: 'Action history' },
    { id: 'playbooks', label: 'Playbooks' }, { id: 'assets', label: 'Asset levels', adminOnly: true },
    { id: 'settings', label: 'Settings', adminOnly: true },
  ]
  return (
    <main className="mx-auto max-w-6xl px-6 py-6">
      <h1 className="mb-1 text-xl font-semibold">SOAR — automated response</h1>
      <p className="mb-4 text-sm text-gray-500">Earned autonomy on Wazuh active response. Every action is audited; nothing runs on the hot path.</p>
      <Metrics token={token} />
      <div className="mb-4 flex gap-4 border-b border-gray-200 dark:border-gray-700">
        {tabs.filter((t) => isAdmin || !t.adminOnly).map((t) => (
          <button key={t.id} onClick={() => setTab(t.id)}
            className={`-mb-px border-b-2 px-1 py-2 text-sm ${tab === t.id ? 'border-indigo-600 text-indigo-600' : 'border-transparent text-gray-500'}`}>{t.label}</button>
        ))}
      </div>
      {tab === 'approvals' && <Approvals token={token} />}
      {tab === 'history' && <History token={token} />}
      {tab === 'playbooks' && <Playbooks token={token} isAdmin={!!isAdmin} />}
      {tab === 'assets' && isAdmin && <AssetLevels token={token} />}
      {tab === 'settings' && isAdmin && <Settings token={token} />}
    </main>
  )
}
