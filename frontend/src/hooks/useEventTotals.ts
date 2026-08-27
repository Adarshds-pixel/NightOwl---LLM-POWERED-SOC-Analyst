import { useEffect, useState } from 'react'
import { getEvents } from '../api'

/**
 * Total ingested events, fetched with limit=1 so the response is a single
 * row plus the server-side `total` -- the cheap way to ask "how much
 * telemetry is in there?" without pulling a page of data nobody renders.
 */
export function useEventTotals() {
  const [eventTotal, setEventTotal] = useState(0)
  const [alertTotal, setAlertTotal] = useState(0)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false

    Promise.all([getEvents({ limit: 1 }), getEvents({ limit: 1, alert_only: true })])
      .then(([all, alerting]) => {
        if (cancelled) return
        setEventTotal(all.total)
        setAlertTotal(alerting.total)
      })
      .catch(() => {
        // Totals are supporting context, never the only thing on screen --
        // a failure here leaves zeros rather than blocking the page.
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })

    return () => {
      cancelled = true
    }
  }, [])

  return { eventTotal, alertTotal, loading }
}
