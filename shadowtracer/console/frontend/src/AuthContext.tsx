import { createContext, useCallback, useContext, useState, type ReactNode } from 'react'
import * as api from './api'

interface Session {
  accessToken: string
  tenantId: number
  role: string
}

interface AuthContextValue {
  session: Session | null
  login: (email: string, password: string) => Promise<void>
  logout: () => Promise<void>
}

// The access token lives only in React state (memory) - never
// localStorage/sessionStorage, which a successful XSS could read. The
// refresh token never reaches JavaScript at all (httpOnly cookie).
const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<Session | null>(null)

  const login = useCallback(async (email: string, password: string) => {
    const resp = await api.login(email, password)
    setSession({ accessToken: resp.access_token, tenantId: resp.tenant_id, role: resp.role })
  }, [])

  const logout = useCallback(async () => {
    await api.logout()
    setSession(null)
  }, [])

  return <AuthContext.Provider value={{ session, login, logout }}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
