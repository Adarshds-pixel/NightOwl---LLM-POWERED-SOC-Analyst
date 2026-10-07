import { useCallback, useEffect, useState } from 'react'
import { getRules, type RuleInfo } from '../api'

/**
 * The loaded detection rule set (GET /rules).
 *
 * Rule *definitions* only change when someone edits a YAML file and restarts
 * the backend, so the result is memoised for the session rather than
 * refetched by every component that wants it (the command palette, the
 * pipeline panel, the MITRE page and the rules page all do). The memo is
 * dropped by refresh(), which is what the pages call after an ingest so the
 * per-rule match counts -- the part that does change -- are re-read.
 */
let cachedRules: RuleInfo[] | null = null
// Mounted consumers re-fetch when the cache is invalidated (after an upload
// or a demo reset) -- before, only components mounted later saw new counts,
// so the always-mounted command palette and pipeline panel stayed stale.
const listeners = new Set<() => void>()

export function invalidateRulesCache(): void {
  cachedRules = null
  listeners.forEach((listener) => listener())
}

export function useRules() {
  const [rules, setRules] = useState<RuleInfo[]>(cachedRules ?? [])
  const [loading, setLoading] = useState(cachedRules === null)
  const [error, setError] = useState<string | null>(null)
  const [generation, setGeneration] = useState(0)

  const refresh = useCallback(() => {
    invalidateRulesCache()
  }, [])

  useEffect(() => {
    const listener = () => setGeneration((g) => g + 1)
    listeners.add(listener)
    return () => {
      listeners.delete(listener)
    }
  }, [])

  useEffect(() => {
    if (cachedRules !== null) {
      setRules(cachedRules)
      setLoading(false)
      return
    }

    let cancelled = false
    setLoading(true)

    getRules()
      .then((response) => {
        cachedRules = response.rules
        if (cancelled) return
        setRules(response.rules)
        setError(null)
      })
      .catch((err: Error) => {
        if (!cancelled) setError(err.message)
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })

    return () => {
      cancelled = true
    }
  }, [generation])

  return { rules, loading, error, refresh }
}
