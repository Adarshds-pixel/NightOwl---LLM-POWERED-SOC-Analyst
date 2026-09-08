import { createContext } from 'react'

/** `null` = "don't know yet" (the initial GET /auth/me check is still in
 *  flight) -- distinct from `false` ("checked, definitely not logged in")
 *  so a route guard can show a brief loading state on first load / a hard
 *  refresh instead of flashing the login page before the real answer comes
 *  back. See AuthProvider.tsx. */
export type AuthStatus = 'checking' | 'authenticated' | 'unauthenticated'

export interface AuthState {
  status: AuthStatus
  username: string | null
  /** Generic, user-facing message only -- never "wrong password" vs "wrong
   *  username" (see routes_auth.py's own reasoning for why the backend
   *  never distinguishes those either). */
  error: string | null
  login: (username: string, password: string) => Promise<void>
  logout: () => Promise<void>
}

export const AuthContext = createContext<AuthState | null>(null)
