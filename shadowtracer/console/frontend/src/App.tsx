import { useState } from 'react'
import { AlertsPage } from './AlertsPage'
import { AuthProvider, useAuth } from './AuthContext'
import { FingerprintDetailPage } from './FingerprintDetailPage'
import { FingerprintsPage } from './FingerprintsPage'
import { IncidentDetailPage } from './IncidentDetailPage'
import { IncidentsPage } from './IncidentsPage'
import { LoginPage } from './LoginPage'

// A handful of screens - deliberately no router library for this: one
// piece of view state plus whatever id/key the current screen needs.
type View =
  | { name: 'alerts' }
  | { name: 'incidents' }
  | { name: 'incident'; id: number }
  | { name: 'fingerprints' }
  | { name: 'fingerprint'; key: string }

function NavBar({ view, onNavigate }: { view: View; onNavigate: (v: View) => void }) {
  const { logout } = useAuth()
  const tabs: { label: string; view: View }[] = [
    { label: 'Alerts', view: { name: 'alerts' } },
    { label: 'Incidents', view: { name: 'incidents' } },
    { label: 'Attack library', view: { name: 'fingerprints' } },
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
      <button onClick={() => void logout()} className="text-sm text-gray-500 hover:text-gray-700">
        Sign out
      </button>
    </header>
  )
}

function AppContent() {
  const { session, restoring } = useAuth()
  const [view, setView] = useState<View>({ name: 'alerts' })

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
