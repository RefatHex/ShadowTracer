import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react'
import * as api from './api'

interface Session {
  accessToken: string
  tenantId: number
  role: string
}

interface AuthContextValue {
  session: Session | null
  restoring: boolean
  login: (email: string, password: string) => Promise<void>
  logout: () => Promise<void>
}

// The access token lives only in React state (memory) - never
// localStorage/sessionStorage, which a successful XSS could read. The
// refresh token never reaches JavaScript at all (httpOnly cookie).
const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<Session | null>(null)
  // True only for the one-time check below - without it, a page reload
  // would always show the login form for a moment (or permanently, if a
  // caller doesn't wait for it) even when the refresh cookie is still
  // good, since `session` itself always starts null.
  const [restoring, setRestoring] = useState(true)

  useEffect(() => {
    let cancelled = false
    api.refresh()
      .then((resp) => {
        if (!cancelled && resp.access_token) {
          setSession({ accessToken: resp.access_token, tenantId: resp.tenant_id, role: resp.role })
        }
      })
      .catch(() => {
        // No valid refresh cookie (first visit, expired, logged out
        // elsewhere) - stay logged out, same as any other failed auth.
      })
      .finally(() => {
        if (!cancelled) setRestoring(false)
      })
    return () => {
      cancelled = true
    }
  }, [])

  const login = useCallback(async (email: string, password: string) => {
    const resp = await api.login(email, password)
    setSession({ accessToken: resp.access_token, tenantId: resp.tenant_id, role: resp.role })
  }, [])

  const logout = useCallback(async () => {
    await api.logout()
    setSession(null)
  }, [])

  return <AuthContext.Provider value={{ session, restoring, login, logout }}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
