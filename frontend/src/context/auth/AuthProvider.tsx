import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'
import { ApiError, getCurrentSession, login as apiLogin, logout as apiLogout, setUnauthorizedHandler } from '../../api'
import { AuthContext, type AuthStatus } from './AuthContext'

/**
 * Single-admin session state. Backed entirely by the signed HttpOnly
 * session cookie the backend sets on POST /auth/login (see
 * backend/app/api/routes_auth.py) -- this provider holds no token itself,
 * only a client-side mirror of "does a valid session currently exist,"
 * refreshed by calling GET /auth/me. The cookie, not this state, is what
 * actually gates every protected API request; losing this state (a hard
 * refresh) never logs the admin out, and losing the cookie (expiry, or a
 * request from a browser that never had it) is always caught server-side
 * regardless of what this component believes.
 */
export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<AuthStatus>('checking')
  const [username, setUsername] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  // One-time check on mount (and effectively on every hard refresh, since
  // that remounts the whole app) -- this is what makes "refresh doesn't log
  // you out" true: the cookie already exists in the browser, this just asks
  // the backend to confirm it's still valid.
  useEffect(() => {
    let cancelled = false
    getCurrentSession()
      .then((res) => {
        if (cancelled) return
        setUsername(res.username)
        setStatus('authenticated')
      })
      .catch(() => {
        if (cancelled) return
        setStatus('unauthenticated')
      })
    return () => {
      cancelled = true
    }
  }, [])

  // Registered once, for the lifetime of the app: any OTHER request
  // anywhere (not the /auth/* calls themselves, see client.ts's
  // UNAUTHORIZED_EXEMPT_PATHS) coming back 401 means the session died
  // between page loads -- expired, or invalidated by a logout from another
  // tab -- so drop straight to unauthenticated rather than waiting for
  // whatever hook happened to notice to report its own error.
  useEffect(() => {
    setUnauthorizedHandler(() => {
      setUsername(null)
      setStatus('unauthenticated')
    })
    return () => setUnauthorizedHandler(null)
  }, [])

  const login = useCallback(async (usernameInput: string, password: string) => {
    setError(null)
    try {
      const res = await apiLogin(usernameInput, password)
      setUsername(res.username)
      setStatus('authenticated')
    } catch (err) {
      // Already generic from the backend ("Invalid credentials.") -- never
      // reveals which field was wrong, see routes_auth.py.
      setError(err instanceof ApiError ? err.detail : 'Could not reach NightOwl. Check your connection and try again.')
      throw err
    }
  }, [])

  const logout = useCallback(async () => {
    try {
      await apiLogout()
    } finally {
      // Clear local state even if the request itself failed (network down,
      // backend unreachable) -- per the task's own "handle logout failures
      // gracefully" requirement, the admin should never be stuck unable to
      // leave a session locally just because one DELETE-ish request failed;
      // worst case the server-side cookie simply expires on its own later.
      setUsername(null)
      setStatus('unauthenticated')
    }
  }, [])

  const value = useMemo(
    () => ({ status, username, error, login, logout }),
    [status, username, error, login, logout],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
