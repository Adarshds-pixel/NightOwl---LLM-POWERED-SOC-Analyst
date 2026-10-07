import { useEffect, useState } from 'react'
import { getSystemStatus, type SystemStatusResponse } from '../api'

const REFRESH_MS = 60_000

// One shared in-flight/cached value for every badge on the page.
let cached: { at: number; value: SystemStatusResponse } | null = null
let inflight: Promise<SystemStatusResponse> | null = null

function load(): Promise<SystemStatusResponse> {
  if (cached && Date.now() - cached.at < REFRESH_MS) return Promise.resolve(cached.value)
  if (!inflight) {
    inflight = getSystemStatus()
      .then((value) => {
        cached = { at: Date.now(), value }
        return value
      })
      .finally(() => {
        inflight = null
      })
  }
  return inflight
}

/** Drop the cached status (e.g. on logout). */
export function resetSystemStatusCache() {
  cached = null
}

/**
 * What is actually configured and loaded on the backend. `aiReady` is true
 * only when an LLM key is configured AND the knowledge base is built -- the
 * honest meaning of "AI available" (it does not spend a paid LLM call to
 * prove the provider is up; a provider outage still surfaces as a clear
 * error on the request that hits it).
 */
export function useSystemStatus() {
  const [status, setStatus] = useState<SystemStatusResponse | null>(cached?.value ?? null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    const tick = () =>
      load()
        .then((value) => {
          if (!cancelled) {
            setStatus(value)
            setError(null)
          }
        })
        .catch((err) => {
          if (!cancelled) setError((err as Error).message)
        })
    void tick()
    const timer = window.setInterval(() => void tick(), REFRESH_MS)
    return () => {
      cancelled = true
      window.clearInterval(timer)
    }
  }, [])

  const aiReady = Boolean(status?.llm.ready && status?.knowledge_base.ready)
  return { status, error, aiReady }
}
