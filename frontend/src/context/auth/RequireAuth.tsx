import type { ReactNode } from 'react'
import { Navigate, useLocation } from 'react-router-dom'
import { LoadingState } from '../../components/ui'
import { useAuth } from './useAuth'

/** Wraps the protected route group in App.tsx. While the initial GET
 *  /auth/me check is in flight ('checking'), shows a loading state rather
 *  than redirecting -- a hard refresh on e.g. /incidents/42 must not flash
 *  the login page before the real answer comes back, or "refresh preserves
 *  the session" would be true in practice but not in what the user sees. */
export function RequireAuth({ children }: { children: ReactNode }) {
  const { status } = useAuth()
  const location = useLocation()

  if (status === 'checking') {
    return (
      <div className="flex h-screen items-center justify-center">
        <LoadingState label="Checking session" />
      </div>
    )
  }

  if (status === 'unauthenticated') {
    // `state.from` lets the login page send the admin back to whatever page
    // they were trying to reach. Deliberately no attempt to distinguish
    // "never logged in" from "session just expired" here -- both collapse
    // to the same `status`, and guessing which one happened would risk
    // showing a false "session expired" message on a plain first visit.
    return <Navigate to="/login" replace state={{ from: location.pathname }} />
  }

  return <>{children}</>
}
