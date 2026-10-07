import { useEffect, useRef, useState } from 'react'
import { getEvents, type EventLogRow } from '../api'
import { backoffMultiplier, countFailure, isDocumentVisible } from '../lib/polling'

/**
 * The dashboard Live Log Stream. Polls the newest slice of GET /events on
 * an interval the user controls (Settings > Data), because the backend has
 * no websocket or SSE endpoint -- and building one purely so the UI can
 * feel live would be backend scope with no other consumer.
 *
 * `paused` freezes the feed while the pointer is inside it, so a row cannot
 * slide out from under a click. The poll also skips hidden tabs entirely
 * and backs off exponentially while the API is throttling, so a background
 * dashboard cannot sit there consuming the request budget that the page the
 * analyst is actually looking at needs.
 */
export function useLiveLogStream(limit = 12, intervalMs = 10_000, paused = false) {
  const [events, setEvents] = useState<EventLogRow[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [lastUpdated, setLastUpdated] = useState<number | null>(null)
  const pausedRef = useRef(paused)
  pausedRef.current = paused
  const [generation, setGeneration] = useState(0)

  useEffect(() => {
    let cancelled = false
    let throttleFailures = 0
    let ticksSkipped = 0

    async function poll(initial: boolean) {
      if (!initial) {
        if (pausedRef.current || !isDocumentVisible()) return
        // Still inside the backoff window after a 429: skip this tick.
        if (++ticksSkipped < backoffMultiplier(throttleFailures)) return
        ticksSkipped = 0
      }

      try {
        const response = await getEvents({ limit })
        if (cancelled) return
        throttleFailures = 0
        setEvents(response.events)
        setLastUpdated(Date.now())
        setError(null)
      } catch (err) {
        if (cancelled) return
        throttleFailures = countFailure(err, throttleFailures)
        setError((err as Error).message)
      } finally {
        if (!cancelled && initial) setLoading(false)
      }
    }

    void poll(true)
    const timer = intervalMs > 0 ? window.setInterval(() => void poll(false), intervalMs) : undefined

    return () => {
      cancelled = true
      if (timer) window.clearInterval(timer)
    }
  }, [limit, intervalMs, generation])

  // Re-fetch this panel only (the retry button used to reload the whole page,
  // which the throttled-state auto-retry could repeat in a loop).
  const refresh = () => setGeneration((g) => g + 1)

  return { events, loading, error, lastUpdated, refresh }
}
