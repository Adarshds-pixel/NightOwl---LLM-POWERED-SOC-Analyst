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
 *
 * `stalled` covers two cases that used to leave a caller's "pending"
 * spinner running forever, found live during this feature's audit: (1)
 * the poll genuinely exhausts MAX_POLL_ATTEMPTS while the opinion is still
 * "pending" server-side (the background LLM call never reached a terminal
 * status in time), and (2) a fetch itself fails, which can happen before
 * `opinion` is ever set at all, so a caller checking only `!opinion`
 * would have no way to tell "haven't heard back yet" apart from "never
 * going to hear back." Both are reported through this one flag so a
 * caller has a single, reliable "give up and show something" signal;
 * `error` still carries the specific message when there is one.
 */
export function useAiOpinion(opinionId: number | null) {
  const [opinion, setOpinion] = useState<AiOpinionResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [stalled, setStalled] = useState(false)
  const attemptsRef = useRef(0)

  useEffect(() => {
    if (opinionId === null) {
      setOpinion(null)
      setError(null)
      setStalled(false)
      return
    }

    let cancelled = false
    attemptsRef.current = 0
    setStalled(false)
    setError(null)

    function poll() {
      getAiOpinion(opinionId as number)
        .then((res) => {
          if (cancelled) return
          setOpinion(res)
          attemptsRef.current += 1
          if (res.status === 'pending') {
            if (attemptsRef.current < MAX_POLL_ATTEMPTS) {
              setTimeout(poll, POLL_INTERVAL_MS)
            } else {
              setStalled(true)
            }
          }
        })
        .catch((err: Error) => {
          if (cancelled) return
          setError(err.message)
          setStalled(true)
        })
    }
    poll()

    return () => {
      cancelled = true
    }
  }, [opinionId])

  return { opinion, error, stalled }
}
