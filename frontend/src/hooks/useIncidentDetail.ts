import { useCallback, useEffect, useState } from 'react'
import { getIncident, type IncidentDetailResponse } from '../api'

export function useIncidentDetail(id: number) {
  const [incident, setIncident] = useState<IncidentDetailResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(() => {
    setLoading(true)
    setError(null)
    getIncident(id)
      .then(setIncident)
      .catch((err: Error) => setError(err.message))
      .finally(() => setLoading(false))
  }, [id])

  useEffect(() => {
    load()
  }, [load])

  return { incident, loading, error, refresh: load }
}
