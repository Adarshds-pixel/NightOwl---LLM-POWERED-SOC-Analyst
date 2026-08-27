import { useCallback, useState } from 'react'
import { ApiError, ingestEvtxFile, type IngestResponse } from '../api'
import { useIncidentsSnapshot } from '../context/incidents/useIncidentsSnapshot'
import { invalidateRulesCache } from './useRules'

export function useLogIngest() {
  const { refresh } = useIncidentsSnapshot()
  const [pending, setPending] = useState(false)
  const [result, setResult] = useState<IngestResponse | null>(null)
  const [error, setError] = useState<string | null>(null)

  const upload = useCallback(
    async (file: File) => {
      setPending(true)
      setError(null)
      setResult(null)
      try {
        const res = await ingestEvtxFile(file)
        setResult(res)
        // An ingest changes both the incident snapshot and the per-rule match
        // counts, so the session-cached rule set has to be dropped too --
        // otherwise the Rules page would keep showing pre-ingest counts.
        invalidateRulesCache()
        refresh()
        return res
      } catch (err) {
        setError(err instanceof ApiError ? err.detail : 'Failed to ingest file')
        return null
      } finally {
        setPending(false)
      }
    },
    [refresh],
  )

  return { pending, result, error, upload }
}
