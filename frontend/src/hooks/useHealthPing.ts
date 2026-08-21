import { useEffect, useState } from 'react'
import { getHealth } from '../api'
import { HEALTH_POLL_INTERVAL_MS } from '../lib/constants'

export type HealthStatus = 'checking' | 'healthy' | 'unreachable'

export function useHealthPing() {
  const [status, setStatus] = useState<HealthStatus>('checking')
  const [lastCheckedAt, setLastCheckedAt] = useState<Date | null>(null)

  useEffect(() => {
    let cancelled = false

    async function ping() {
      try {
        await getHealth()
        if (!cancelled) setStatus('healthy')
      } catch {
        if (!cancelled) setStatus('unreachable')
      } finally {
        if (!cancelled) setLastCheckedAt(new Date())
      }
    }

    ping()
    const interval = setInterval(ping, HEALTH_POLL_INTERVAL_MS)
    return () => {
      cancelled = true
      clearInterval(interval)
    }
  }, [])

  return { status, lastCheckedAt }
}
