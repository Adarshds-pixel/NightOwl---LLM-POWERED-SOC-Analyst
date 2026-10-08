import { useCallback, useState } from 'react'
import { ApiError, ingestEvtxFileWithProgress, type IngestResponse } from '../api'
import { useIncidentsSnapshot } from '../context/incidents/useIncidentsSnapshot'
import { invalidateRulesCache } from './useRules'

export type IngestPhase = 'idle' | 'uploading' | 'processing' | 'done'

export function useLogIngest() {
  const { refresh } = useIncidentsSnapshot()
  const [pending, setPending] = useState(false)
  const [phase, setPhase] = useState<IngestPhase>('idle')
  const [progress, setProgress] = useState(0)
  const [recordsRead, setRecordsRead] = useState(0)
  const [result, setResult] = useState<IngestResponse | null>(null)
  const [error, setError] = useState<string | null>(null)

  const upload = useCallback(
    async (file: File) => {
      setPending(true)
      setPhase('uploading')
      setProgress(0)
      setRecordsRead(0)
      setError(null)
      setResult(null)
      try {
        const res = await ingestEvtxFileWithProgress(file, (fraction) => {
          setProgress(fraction)
          // The transfer hitting 100% doesn't mean the request is done --
          // the server still has to parse/normalize/detect with no
          // progress channel of its own, so this switches to a distinct
          // label rather than leaving the bar frozen at 100% with no
          // indication anything is still happening.
          if (fraction >= 1) setPhase('processing')
        }, (job) => setRecordsRead(job.records_read))
        setResult(res)
        setPhase('done')
        // An ingest changes both the incident snapshot and the per-rule match
        // counts, so the session-cached rule set has to be dropped too --
        // otherwise the Rules page would keep showing pre-ingest counts.
        invalidateRulesCache()
        refresh()
        return res
      } catch (err) {
        setError(err instanceof ApiError ? err.detail : 'Failed to ingest file')
        setPhase('idle')
        return null
      } finally {
        setPending(false)
      }
    },
    [refresh],
  )

  return { pending, phase, progress, recordsRead, result, error, upload }
}
