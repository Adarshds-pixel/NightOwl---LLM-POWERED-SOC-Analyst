import type { ReactNode } from 'react'
import { Navigate } from 'react-router-dom'
import { useAuth } from './useAuth'

/** Wraps the /login route so an already-authenticated admin visiting
 *  /login directly (e.g. an old bookmark, or clicking back) lands on the
 *  Dashboard instead of seeing the sign-in form again. While the initial
 *  session check is still in flight, renders nothing rather than briefly
 *  flashing the login form before possibly redirecting away from it. */
export function RedirectIfAuthenticated({ children }: { children: ReactNode }) {
  const { status } = useAuth()

  if (status === 'checking') return null
  if (status === 'authenticated') return <Navigate to="/" replace />

  return <>{children}</>
}
