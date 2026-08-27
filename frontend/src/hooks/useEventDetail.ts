import { useEffect, useState } from 'react'
import { getEvent, type EventDetailResponse } from '../api'

/** Raw record behind one log row (GET /events/{id}). Only fetched when a
 *  row is actually expanded -- raw_json is by far the largest column and
 *  the list endpoint deliberately omits it. */
export function useEventDetail(eventId: number | null) {
  const [event, setEvent] = useState<EventDetailResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (eventId === null) {
      setEvent(null)
      setError(null)
      return
    }

    let cancelled = false
    setLoading(true)

    getEvent(eventId)
      .then((response) => {
        if (!cancelled) {
          setEvent(response)
          setError(null)
        }
      })
      .catch((err: Error) => {
        if (!cancelled) setError(err.message)
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })

    return () => {
      cancelled = true
    }
  }, [eventId])

  return { event, loading, error }
}
