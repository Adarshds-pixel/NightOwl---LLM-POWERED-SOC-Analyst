import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { pingHealth } from '../../api'
import { HEALTH_POLL_INTERVAL_MS } from '../../lib/constants'
import { isDocumentVisible } from '../../lib/polling'
import { HealthContext, type HealthStatus } from './HealthContext'

const MAX_SAMPLES = 24

/**
 * One health poll for the whole app. Previously the top bar and the system
 * panel each ran their own useHealthPing, doubling the request rate for the
 * same answer; lifting it here also lets the Pipeline Health panel show a
 * real latency history rather than a single instantaneous reading.
 *
 * The poll pauses while the tab is hidden -- a background tab does not need
 * to know the API is up, and the check is not free -- and resumes with an
 * immediate probe when the tab comes back, so returning to the window never
 * shows a stale status.
 */
export function HealthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<HealthStatus>('checking')
  const [latencyMs, setLatencyMs] = useState<number | null>(null)
  const [samples, setSamples] = useState<number[]>([])
  const [lastCheckedAt, setLastCheckedAt] = useState<number | null>(null)
  const [generation, setGeneration] = useState(0)
  const mounted = useRef(true)

  const refresh = useCallback(() => setGeneration((g) => g + 1), [])

  useEffect(() => {
    mounted.current = true

    // `initial` bypasses the visibility check: a tab that is loaded in the
    // background (opened via middle-click, restored on startup, or simply
    // not focused) must still resolve its status once, or the UI sits on
    // "Checking..." forever and reports the API as offline.
    async function check(initial = false) {
      if (!initial && !isDocumentVisible()) return
      const result = await pingHealth()
      if (!mounted.current) return
      // A throttled probe means the API answered, just not this request --
      // reporting that as "unreachable" would be a lie about the backend.
      setStatus(result.ok || result.throttled ? 'healthy' : 'unreachable')
      setLastCheckedAt(Date.now())
      if (result.ok) {
        setLatencyMs(result.latencyMs)
        setSamples((current) => [...current, Math.round(result.latencyMs)].slice(-MAX_SAMPLES))
      } else if (!result.throttled) {
        setLatencyMs(null)
      }
    }

    void check(true)
    const timer = window.setInterval(() => void check(), HEALTH_POLL_INTERVAL_MS)
    // Coming back to the tab re-checks immediately, so a returning analyst
    // never reads a status that went stale while the tab was hidden.
    const onVisible = () => void check(true)
    document.addEventListener('visibilitychange', onVisible)

    return () => {
      mounted.current = false
      window.clearInterval(timer)
      document.removeEventListener('visibilitychange', onVisible)
    }
  }, [generation])

  const value = useMemo(
    () => ({ status, latencyMs, samples, lastCheckedAt, refresh }),
    [status, latencyMs, samples, lastCheckedAt, refresh],
  )

  return <HealthContext.Provider value={value}>{children}</HealthContext.Provider>
}
