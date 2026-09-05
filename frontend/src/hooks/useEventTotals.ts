import { useCallback, useEffect, useRef, useState } from 'react'
import { getEvents } from '../api'

/**
 * Total ingested events, fetched with limit=1 so the response is a single
 * row plus the server-side `total` -- the cheap way to ask "how much
 * telemetry is in there?" without pulling a page of data nobody renders.
 *
 * Exposes `refresh` (same shape as useEvents.ts's own `refresh: load`) so
 * a caller that just ingested a new file can ask these totals to catch up
 * immediately -- without it, these numbers only ever reflected whatever
 * was in the store the moment this hook first mounted, and silently went
 * stale after every upload on the same page load until a full reload.
 *
 * `requestId` guards against a second, real bug that same fix uncovered:
 * calling `refresh()` again before the previous call's 3 requests have
 * resolved (e.g. two uploads a few seconds apart) starts a second,
 * independent set of promises with no relationship to the first. Network
 * timing does not guarantee the first set resolves before the second, so
 * without this guard an older, slower response can land *after* a newer
 * one and silently overwrite it with stale totals -- observed live as the
 * cards freezing for several uploads in a row before catching up. Each
 * call captures the request id current at its own start and only applies
 * its result if that id is still the latest when it resolves.
 */
export function useEventTotals() {
  const [eventTotal, setEventTotal] = useState(0)
  const [alertTotal, setAlertTotal] = useState(0)
  // Events no loaded rule could ever evaluate -- distinct from "evaluated,
  // no match" (genuinely clean). See ListEventsParams.covered's doc comment.
  const [uncoveredTotal, setUncoveredTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const requestId = useRef(0)

  const load = useCallback(() => {
    const thisRequest = ++requestId.current
    setLoading(true)
    Promise.all([
      getEvents({ limit: 1 }),
      getEvents({ limit: 1, alert_only: true }),
      getEvents({ limit: 1, covered: false }),
    ])
      .then(([all, alerting, uncovered]) => {
        if (thisRequest !== requestId.current) return
        setEventTotal(all.total)
        setAlertTotal(alerting.total)
        setUncoveredTotal(uncovered.total)
      })
      .catch(() => {
        // Totals are supporting context, never the only thing on screen --
        // a failure here leaves the previous values rather than blocking
        // the page or zeroing out an otherwise-correct display.
      })
      .finally(() => {
        if (thisRequest === requestId.current) setLoading(false)
      })
  }, [])

  useEffect(() => {
    load()
  }, [load])

  return { eventTotal, alertTotal, uncoveredTotal, loading, refresh: load }
}
