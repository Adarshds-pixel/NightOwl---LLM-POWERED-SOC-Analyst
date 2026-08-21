import { useCallback, useEffect, useRef, useState } from 'react'
import { explainIncident, type ExplainResponse } from '../api'

// Cosmetic only -- the underlying call is the single real POST /explain
// request; these labels just narrate what that pipeline is actually doing
// server-side (retrieve -> draft -> self-critique) while it's in flight.
// The stage timer never fabricates a result: if the real request finishes
// before all stages have shown, the result is used immediately regardless
// of stageIndex.
export const EXPLAIN_STAGES = [
  'Retrieving incident context...',
  'Searching MITRE knowledge base...',
  'Drafting explanation...',
  'Running self-critique...',
] as const

const STAGE_INTERVAL_MS = 900

export type ExplainStatus = 'idle' | 'loading' | 'success' | 'error'

const CONFIDENCE_CHECK_MARKER = '**Confidence check:**'

export function useExplain(incidentId: number) {
  const [status, setStatus] = useState<ExplainStatus>('idle')
  const [stageIndex, setStageIndex] = useState(0)
  const [result, setResult] = useState<ExplainResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const clearTimer = useCallback(() => {
    if (timerRef.current) {
      clearInterval(timerRef.current)
      timerRef.current = null
    }
  }, [])

  const run = useCallback(() => {
    setStatus('loading')
    setStageIndex(0)
    setError(null)
    clearTimer()
    timerRef.current = setInterval(() => {
      setStageIndex((i) => Math.min(i + 1, EXPLAIN_STAGES.length - 1))
    }, STAGE_INTERVAL_MS)

    explainIncident(incidentId)
      .then((res) => {
        setResult(res)
        setStatus('success')
      })
      .catch((err: Error) => {
        setError(err.message)
        setStatus('error')
      })
      .finally(clearTimer)
  }, [incidentId, clearTimer])

  useEffect(() => clearTimer, [clearTimer])

  const selfCritiqueFlagged = result?.explanation.includes(CONFIDENCE_CHECK_MARKER) ?? false

  return { status, stageIndex, result, error, selfCritiqueFlagged, run }
}
