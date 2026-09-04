import { useEffect, useRef, useState } from 'react'
import { getAiOpinion, type AiOpinionResponse } from '../api'

const POLL_INTERVAL_MS = 2000
// ~60s cap -- comfortably past llm_client.py's own ~30s timeout + one retry,
// so a genuinely stuck poll gives up instead of running forever.
const MAX_POLL_ATTEMPTS = 30

/**
 * Polls GET /ai-opinions/{id} until it leaves "pending", starting from
 * `opinionId` (pass null when there's nothing to poll -- e.g. a fully
 * covered ingest with no advisory opinion). Advisory only: this hook's
 * result must never be styled or treated like a real Alert/Incident --
 * see AiOpinionPanel for the "not a verified detection" framing this
 * feeds.
 */
export function useAiOpinion(opinionId: number | null) {
  const [opinion, setOpinion] = useState<AiOpinionResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const attemptsRef = useRef(0)

  useEffect(() => {
    if (opinionId === null) {
      setOpinion(null)
      setError(null)
      return
    }

    let cancelled = false
    attemptsRef.current = 0

    function poll() {
      getAiOpinion(opinionId as number)
        .then((res) => {
          if (cancelled) return
          setOpinion(res)
          attemptsRef.current += 1
          if (res.status === 'pending' && attemptsRef.current < MAX_POLL_ATTEMPTS) {
            setTimeout(poll, POLL_INTERVAL_MS)
          }
        })
        .catch((err: Error) => {
          if (!cancelled) setError(err.message)
        })
    }
    poll()

    return () => {
      cancelled = true
    }
  }, [opinionId])

  return { opinion, error }
}
