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
  // Events no loaded rule could ever evaluate -- distinct from "evaluated,
  // no match" (genuinely clean). See ListEventsParams.covered's doc comment.
  const [uncoveredTotal, setUncoveredTotal] = useState(0)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false

    Promise.all([
      getEvents({ limit: 1 }),
      getEvents({ limit: 1, alert_only: true }),
      getEvents({ limit: 1, covered: false }),
    ])
      .then(([all, alerting, uncovered]) => {
        if (cancelled) return
        setEventTotal(all.total)
        setAlertTotal(alerting.total)
        setUncoveredTotal(uncovered.total)
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

  return { eventTotal, alertTotal, uncoveredTotal, loading }
}
