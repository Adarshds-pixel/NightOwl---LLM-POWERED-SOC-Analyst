import { useCallback, useEffect, useState } from 'react'
import { getEvents, type EventLogRow } from '../api'
import { EVENT_PAGE_SIZE } from '../lib/constants'

export interface EventFilters {
  host: string
  alertOnly: boolean
}

// The Logs page's data hook -- genuinely paginated one page at a time
// (see EVENT_PAGE_SIZE's comment), unlike the eager-fetch-everything
// pattern useIncidentDetail/IncidentsDataProvider use elsewhere. Changing
// a filter resets back to page 0, same as changing filters on any real
// paginated list would.
export function useEvents(filters: EventFilters) {
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
      alert_only: filters.alertOnly || undefined,
      limit: EVENT_PAGE_SIZE,
      offset: page * EVENT_PAGE_SIZE,
    })
      .then((res) => {
        setEvents(res.events)
        setTotal(res.total)
      })
      .catch((err: Error) => setError(err.message))
      .finally(() => setLoading(false))
  }, [filters.host, filters.alertOnly, page])

  useEffect(() => {
    load()
  }, [load])

  useEffect(() => {
    setPage(0)
  }, [filters.host, filters.alertOnly])

  return { events, total, page, setPage, loading, error, refresh: load }
}
