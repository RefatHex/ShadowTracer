import { AlertsPage } from './AlertsPage'
import { AuthProvider, useAuth } from './AuthContext'
import { LoginPage } from './LoginPage'

function AppContent() {
  const { session } = useAuth()
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
