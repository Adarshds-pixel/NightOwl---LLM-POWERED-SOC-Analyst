import { useCallback, useEffect, useState } from 'react'
import { getEvents, type EventLogRow, type ListEventsParams } from '../api'

/**
 * Alerts = events that matched a detection rule. There is no /alerts
 * endpoint: alerts live in the alerts table but are only reachable nested
 * under an incident, or flattened onto GET /events rows (which carry the
 * matched rule title, severity, technique and now the parent incident id).
 * Querying /events with alert_only=true is therefore the real alert feed,
 * not a substitute for one.
 */
export function useAlerts(params: Omit<ListEventsParams, 'alert_only'> = {}, pollMs = 0) {
  const [alerts, setAlerts] = useState<EventLogRow[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [generation, setGeneration] = useState(0)

  const refresh = useCallback(() => setGeneration((g) => g + 1), [])

  const { host, start_date, end_date, q, limit, offset } = params

  useEffect(() => {
    let cancelled = false

    async function load(showSpinner: boolean) {
      if (showSpinner) setLoading(true)
      try {
        const response = await getEvents({ host, start_date, end_date, q, limit, offset, alert_only: true })
        if (cancelled) return
        setAlerts(response.events)
        setTotal(response.total)
        setError(null)
      } catch (err) {
        if (!cancelled) setError((err as Error).message)
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    void load(true)

    // Background refreshes deliberately skip the spinner: a live feed that
    // flashes a skeleton every poll is unreadable.
    const timer = pollMs > 0 ? window.setInterval(() => void load(false), pollMs) : undefined
    return () => {
      cancelled = true
      if (timer) window.clearInterval(timer)
    }
  }, [host, start_date, end_date, q, limit, offset, pollMs, generation])

  return { alerts, total, loading, error, refresh }
}
