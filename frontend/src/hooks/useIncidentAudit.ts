import { useCallback, useEffect, useState } from 'react'
import { getIncidentAudit, type AuditLogResponse } from '../api'

export function useIncidentAudit(id: number) {
  const [audit, setAudit] = useState<AuditLogResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(() => {
    setLoading(true)
    setError(null)
    getIncidentAudit(id)
      .then(setAudit)
      .catch((err: Error) => setError(err.message))
      .finally(() => setLoading(false))
  }, [id])

  useEffect(() => {
    load()
  }, [load])

  return { audit, loading, error, refresh: load }
}
