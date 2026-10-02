import type { Alert } from './api'

// Alert text (message/full_log, rule_description, agent_name, ...) is
// attacker-controlled - it comes from whatever an attacker's SSH client,
// user-agent string, or file path happened to contain. Every field below
// is rendered as a React text child ({value}), never via
// dangerouslySetInnerHTML and never interpolated into an href/src/style
// attribute - React escapes text children automatically, so a value like
// "<script>...</script>" renders as the literal visible characters, not
// as markup. See AlertRow.test.tsx for the actual proof.
export function AlertRow({ alert }: { alert: Alert }) {
  return (
    <tr className="border-b border-gray-200 dark:border-gray-700">
      <td className="px-3 py-2 whitespace-nowrap text-sm text-gray-500">{alert.time}</td>
      <td className="px-3 py-2 text-sm">{alert.agent_name}</td>
      <td className="px-3 py-2 text-sm">
        <span className="font-mono text-xs text-gray-500">{alert.rule_id}</span>{' '}
        <span className="inline-block rounded px-1.5 py-0.5 text-xs bg-amber-100 text-amber-800">
          level {alert.rule_level}
        </span>
      </td>
      <td className="px-3 py-2 text-sm">{alert.rule_description}</td>
      <td className="px-3 py-2 text-sm font-mono text-xs text-gray-600 dark:text-gray-300 break-all">
        {alert.message}
      </td>
    </tr>
  )
}
