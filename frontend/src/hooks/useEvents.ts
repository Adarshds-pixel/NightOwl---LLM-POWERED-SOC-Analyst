import { useCallback, useEffect, useState } from 'react'
import { getEvents, type EventLogRow } from '../api'
import { levelFor } from '../lib/events'
import type { LogLevel } from '../components/ui/Badge'

export interface EventFilters {
  host: string
  /** Free-text search -- server-side (q= on GET /events). */
  search: string
  /** true = only rule-matching events, false = only ordinary events. */
  alertOnly: boolean | null
  /** Client-side narrowing of the fetched page: the API has no level
   *  concept (level is derived from the matched alert severity), so this
   *  filters what came back rather than pretending it is a query param. */
  level: LogLevel | 'all'
  /** Sysmon event id, e.g. 1 for process creation. Also client-side. */
  eventId: number | 'all'
  startDate?: string
  endDate?: string
}

export const EMPTY_EVENT_FILTERS: EventFilters = {
  host: '',
  search: '',
  alertOnly: null,
  level: 'all',
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

  const load = useCallback(() => {
    setLoading(true)
    setError(null)
    getEvents({
      host: filters.host || undefined,
      q: filters.search || undefined,
      alert_only: filters.alertOnly ?? undefined,
      start_date: filters.startDate,
      end_date: filters.endDate,
      limit: pageSize,
      offset: page * pageSize,
    })
      .then((res) => {
        setEvents(res.events)
        setTotal(res.total)
      })
      .catch((err: Error) => setError(err.message))
      .finally(() => setLoading(false))
  }, [filters.host, filters.search, filters.alertOnly, filters.startDate, filters.endDate, page, pageSize])

  useEffect(() => {
    load()
  }, [load])

  useEffect(() => {
    setPage(0)
  }, [filters.host, filters.search, filters.alertOnly, filters.startDate, filters.endDate, pageSize])

  // Level and event-id narrowing happen after the fetch; `total` still
  // reports the server-side total so the pagination footer stays honest
  // about what it is paging through.
  const visible = events.filter((event) => {
    if (filters.level !== 'all' && levelFor(event.severity, event.is_alert) !== filters.level) return false
    if (filters.eventId !== 'all' && event.event_id !== filters.eventId) return false
    return true
  })

  return { events: visible, rawEvents: events, total, page, setPage, loading, error, refresh: load }
}
