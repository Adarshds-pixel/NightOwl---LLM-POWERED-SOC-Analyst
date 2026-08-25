import { useCallback, useState } from 'react'
import { ApiError, ingestEvtxFile, type IngestResponse } from '../api'
import { useIncidentsSnapshot } from '../context/incidents/useIncidentsSnapshot'

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
