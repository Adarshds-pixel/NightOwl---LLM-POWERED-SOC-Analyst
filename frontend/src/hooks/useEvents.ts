import { useCallback, useEffect, useRef, useState } from 'react'
import { getEvents, type EventLogRow, type Severity } from '../api'

export interface EventFilters {
  host: string
  /** Free-text search -- server-side (q= on GET /events). */
  search: string
  /** true = only rule-matching events, false = only ordinary events. */
  alertOnly: boolean | null
  /** Server-side severity narrowing: a real severity keeps only events
   *  carrying an alert of that severity, 'clean' keeps only events that
   *  matched no rule at all. Sent as a query param (not applied to the
   *  fetched page) so `total` and the pagination footer describe the
   *  filtered set, not the unfiltered one. */
  severity: Severity | 'all' | 'clean'
  /** Sysmon event id, e.g. 1 for process creation. Client-side: the API
   *  has no event-id filter, and this only ever narrows one visible page. */
  eventId: number | 'all'
  startDate?: string
  endDate?: string
}

export const EMPTY_EVENT_FILTERS: EventFilters = {
  host: '',
  search: '',
  alertOnly: null,
  severity: 'all',
  eventId: 'all',
}

/**
 * The Logs/Alerts data hook -- genuinely server-paginated one page at a
 * time (a real capture reaches tens of thousands of events, so the
 * eager-fetch pattern the incidents context uses would mean hundreds of
 * requests). Changing any filter resets to page 0.
 */
export function useEvents(filters: EventFilters, pageSize: number) {
  const [page, setPage] = useState(0)
  const [events, setEvents] = useState<EventLogRow[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  // Guards against an older, slower request landing after a newer one and
  // overwriting it with stale data -- see useEventTotals.ts's requestId
  // doc comment for the observed failure mode this prevents.
  const requestId = useRef(0)

  // 'clean' is the "matched no rule" case, which the API expresses as
  // alert_only=false rather than as a severity value.
  const severityParam = filters.severity !== 'all' && filters.severity !== 'clean' ? filters.severity : undefined
  const alertOnlyParam = filters.severity === 'clean' ? false : (filters.alertOnly ?? undefined)

  // Back to page 0 when the filters change -- during render, so the load
  // never fires once with the previous page's offset.
  const filterKey = JSON.stringify([
    filters.host, filters.search, alertOnlyParam, severityParam, filters.startDate, filters.endDate, pageSize,
  ])
  const [appliedKey, setAppliedKey] = useState(filterKey)
  if (appliedKey !== filterKey) {
    setAppliedKey(filterKey)
    setPage(0)
  }
  const effectivePage = appliedKey === filterKey ? page : 0

  const load = useCallback(() => {
    const thisRequest = ++requestId.current
    setLoading(true)
    setError(null)
    getEvents({
      host: filters.host || undefined,
      q: filters.search || undefined,
      alert_only: alertOnlyParam,
      severity: severityParam,
      start_date: filters.startDate,
      end_date: filters.endDate,
      limit: pageSize,
      offset: effectivePage * pageSize,
    })
      .then((res) => {
        if (thisRequest !== requestId.current) return
        setEvents(res.events)
        setTotal(res.total)
      })
      .catch((err: Error) => {
        if (thisRequest === requestId.current) setError(err.message)
      })
      .finally(() => {
        if (thisRequest === requestId.current) setLoading(false)
      })
  }, [filters.host, filters.search, alertOnlyParam, severityParam, filters.startDate, filters.endDate, effectivePage, pageSize])

  useEffect(() => {
    load()
  }, [load])

  // Only event-id narrowing is client-side now (the API has no event-id
  // filter); severity is a real query param, so `total` and the pagination
  // footer describe the filtered set.
  const visible = events.filter((event) => {
    if (filters.eventId !== 'all' && event.event_id !== filters.eventId) return false
    return true
  })

  return { events: visible, rawEvents: events, total, page: effectivePage, setPage, loading, error, refresh: load }
}
