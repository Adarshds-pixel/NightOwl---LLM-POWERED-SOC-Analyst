import { useEffect, type ReactNode } from 'react'
import { invalidateRulesCache } from '../hooks/useRules'
import { resetSystemStatusCache } from '../hooks/useSystemStatus'
import { AppProviders } from './AppProviders'
import { useAuth } from './auth/useAuth'

/**
 * Remounts every app-level data provider (incident snapshot, MITRE catalog,
 * health, toasts...) whenever the signed-in identity changes, so nothing
 * fetched under one session -- incidents, counts, errors -- survives a logout
 * into the next. Module-level caches are dropped at the same moment.
 */
export function SessionScopedProviders({ children }: { children: ReactNode }) {
  const { status, username } = useAuth()
  const sessionKey = status === 'authenticated' ? `user:${username ?? ''}` : 'anonymous'
  return (
    <AppProviders key={sessionKey}>
      <SessionCacheReset sessionKey={sessionKey} />
      {children}
    </AppProviders>
  )
}

let lastSessionKey: string | null = null

function SessionCacheReset({ sessionKey }: { sessionKey: string }) {
  // In an effect, not during render: invalidating notifies mounted
  // useRules consumers, which must not set state mid-render.
  useEffect(() => {
    if (lastSessionKey !== null && lastSessionKey !== sessionKey) {
      invalidateRulesCache()
      resetSystemStatusCache()
    }
    lastSessionKey = sessionKey
  }, [sessionKey])
  return null
}
