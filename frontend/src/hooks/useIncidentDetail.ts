import { useCallback, useEffect, useRef, useState } from 'react'
import { getIncident, type IncidentDetailResponse } from '../api'

export function useIncidentDetail(id: number) {
  const [incident, setIncident] = useState<IncidentDetailResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  // Guards against an older, slower request landing after a newer one and
  // overwriting it with stale data -- same pattern as useEvents.ts's
  // requestId (rapid incident-id navigation, or refresh() called twice in
  // quick succession, could otherwise let a superseded response win).
  const requestId = useRef(0)

  const loadedId = useRef<number | null>(null)

  const load = useCallback(() => {
    const thisRequest = ++requestId.current
    if (!Number.isInteger(id) || id <= 0) {
      setIncident(null)
      setError('Invalid incident reference')
      setLoading(false)
      return
    }
    // Only a different incident shows the full-page spinner; refreshing the
    // same one (after a status change) keeps the page -- and the open chat
    // tab and drawers -- mounted.
    if (loadedId.current !== id) setLoading(true)
    setError(null)
    getIncident(id)
      .then((result) => {
        if (thisRequest !== requestId.current) return
        loadedId.current = id
        setIncident(result)
      })
      .catch((err: Error) => {
        if (thisRequest === requestId.current) setError(err.message)
      })
      .finally(() => {
        if (thisRequest === requestId.current) setLoading(false)
      })
  }, [id])

  useEffect(() => {
    load()
  }, [load])

  return { incident, loading, error, refresh: load }
}
