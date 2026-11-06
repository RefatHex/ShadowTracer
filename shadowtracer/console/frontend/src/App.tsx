import { useEffect, useState } from 'react'
import { AboutPage } from './AboutPage'
import { AlertsPage } from './AlertsPage'
import { AttackCoveragePage } from './AttackCoveragePage'
import { AuthProvider, useAuth } from './AuthContext'
import { fetchVersion } from './api'
import { FingerprintDetailPage } from './FingerprintDetailPage'
import { FingerprintsPage } from './FingerprintsPage'
import { IncidentDetailPage } from './IncidentDetailPage'
import { IncidentsPage } from './IncidentsPage'
import { IocBrowserPage } from './IocBrowserPage'
import { TiSettingsPage } from './TiSettingsPage'
import { LoginPage } from './LoginPage'

// A handful of screens - deliberately no router library for this: one
// piece of view state plus whatever id/key the current screen needs.
type View =
  | { name: 'alerts' }
  | { name: 'incidents' }
  | { name: 'incident'; id: number }
  | { name: 'fingerprints' }
  | { name: 'fingerprint'; key: string }
  | { name: 'attack-coverage' }
  | { name: 'iocs' }
  | { name: 'ti-settings' }
  | { name: 'about' }

function NavBar({ view, onNavigate }: { view: View; onNavigate: (v: View) => void }) {
  const { logout } = useAuth()
  const tabs: { label: string; view: View }[] = [
    { label: 'Alerts', view: { name: 'alerts' } },
    { label: 'Incidents', view: { name: 'incidents' } },
    { label: 'Attack library', view: { name: 'fingerprints' } },
    { label: 'ATT&CK coverage', view: { name: 'attack-coverage' } },
    { label: 'Threat intel', view: { name: 'iocs' } },
    { label: 'TI settings', view: { name: 'ti-settings' } },
  ]
  return (
    <header className="flex items-center justify-between border-b border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 px-6 py-4">
      <nav className="flex gap-4">
        {tabs.map((tab) => (
          <button
            key={tab.label}
            onClick={() => onNavigate(tab.view)}
            className={`text-sm font-medium ${
              view.name === tab.view.name ? 'text-indigo-600' : 'text-gray-500 hover:text-gray-700'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </nav>
      <div className="flex items-center gap-4">
        <button
          onClick={() => onNavigate({ name: 'about' })}
          className={`text-sm ${
            view.name === 'about' ? 'text-indigo-600' : 'text-gray-500 hover:text-gray-700'
          }`}
        >
          About
        </button>
        <button onClick={() => void logout()} className="text-sm text-gray-500 hover:text-gray-700">
          Sign out
        </button>
      </div>
    </header>
  )
}

// Phase 5.6 Item 4: fetched from /health (the backend's own
// shadowtracer/VERSION read), not a separately-hardcoded frontend
// constant - one source of truth, no drift between what the API and the
// console claim to be running.
function Footer() {
  const [version, setVersion] = useState<string | null>(null)

  useEffect(() => {
    fetchVersion()
      .then((h) => setVersion(h.version))
      .catch(() => setVersion(null)) // version display is best-effort, never blocks the UI
  }, [])

  return (
    <footer className="px-6 py-3 text-xs text-gray-400 dark:text-gray-500">
      ShadowTracer{version ? ` v${version}` : ''}
    </footer>
  )
}

// 6.4: a link can open one screen directly (#/incidents/42, #/iocs, #/ti-settings); there
// is still no router - the hash is read on load and whenever it changes.
function viewFromHash(): View {
  const h = window.location.hash
  const incident = /^#\/incidents\/(\d+)$/.exec(h)
  if (incident) return { name: 'incident', id: Number(incident[1]) }
  if (h === '#/iocs') return { name: 'iocs' }
  if (h === '#/ti-settings') return { name: 'ti-settings' }
  return { name: 'alerts' }
}

function AppContent() {
  const { session, restoring } = useAuth()
  const [view, setView] = useState<View>(viewFromHash)

  useEffect(() => {
    const onHash = () => setView(viewFromHash())
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  // Avoid flashing the login form while the one-time refresh-cookie
  // check (AuthContext) is still in flight on page load.
  if (restoring) return null
  if (!session) return <LoginPage />

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      <NavBar view={view} onNavigate={setView} />
      {view.name === 'alerts' && <AlertsPage />}
      {view.name === 'incidents' && <IncidentsPage onOpen={(id) => setView({ name: 'incident', id })} />}
      {view.name === 'incident' && (
        <IncidentDetailPage incidentId={view.id} onBack={() => setView({ name: 'incidents' })} />
      )}
      {view.name === 'fingerprints' && (
        <FingerprintsPage onOpen={(key) => setView({ name: 'fingerprint', key })} />
      )}
      {view.name === 'fingerprint' && (
        <FingerprintDetailPage fingerprintKey={view.key} onBack={() => setView({ name: 'fingerprints' })} />
      )}
      {view.name === 'attack-coverage' && <AttackCoveragePage />}
      {view.name === 'iocs' && <IocBrowserPage />}
      {view.name === 'ti-settings' && <TiSettingsPage />}
      {view.name === 'about' && <AboutPage />}
      <Footer />
    </div>
  )
}

function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  )
}

export default App
