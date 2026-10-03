import { AlertsPage } from './AlertsPage'
import { AuthProvider, useAuth } from './AuthContext'
import { LoginPage } from './LoginPage'

function AppContent() {
  const { session, restoring } = useAuth()
  // Avoid flashing the login form while the one-time refresh-cookie
  // check (AuthContext) is still in flight on page load.
  if (restoring) return null
  return session ? <AlertsPage /> : <LoginPage />
}

function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  )
}

export default App
