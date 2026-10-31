// Rebrand Pass C, Stage 1: GPLv2 attribution notice. No existing page for
// this before - a small standalone screen rather than folding it into
// NavBar's tabs, since it's reference info, not a working view.
export function AboutPage() {
  return (
    <div className="mx-auto max-w-2xl p-8">
      <h1 className="text-xl font-semibold text-gray-900 dark:text-gray-100">About ShadowTracer</h1>
      <p className="mt-4 text-sm text-gray-700 dark:text-gray-300">
        ShadowTracer is built on{' '}
        <a
          href="https://github.com/wazuh/wazuh"
          target="_blank"
          rel="noreferrer"
          className="text-indigo-600 hover:underline"
        >
          Wazuh
        </a>{' '}
        open source (GPLv2).
      </p>
      <p className="mt-2 text-sm text-gray-700 dark:text-gray-300">
        Source availability:{' '}
        <a
          href="https://github.com/RefatHex/ShadowTracer"
          target="_blank"
          rel="noreferrer"
          className="text-indigo-600 hover:underline"
        >
          github.com/RefatHex/ShadowTracer
        </a>
      </p>
    </div>
  )
}
