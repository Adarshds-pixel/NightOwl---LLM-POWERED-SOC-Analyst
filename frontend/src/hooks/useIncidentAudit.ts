import { useCallback, useEffect, useRef, useState } from 'react'
import { getIncidentAudit, type AuditLogResponse } from '../api'

export function useIncidentAudit(id: number) {
  const [audit, setAudit] = useState<AuditLogResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  // Guards against an older, slower request landing after a newer one and
  // overwriting it with stale data -- same pattern as useEvents.ts's
  // requestId. Matters here in particular now that AuditTrail.tsx can
  // trigger an extra refresh() on a status-change signal, on top of the
  // normal mount fetch -- two overlapping calls must not let the older one
  // win.
  const requestId = useRef(0)

  const load = useCallback(() => {
    const thisRequest = ++requestId.current
    setLoading(true)
    setError(null)
    getIncidentAudit(id)
      .then((result) => {
        if (thisRequest === requestId.current) setAudit(result)
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

  return { audit, loading, error, refresh: load }
}
