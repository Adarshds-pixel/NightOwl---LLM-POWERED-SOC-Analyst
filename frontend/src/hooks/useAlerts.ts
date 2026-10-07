import { useCallback, useEffect, useState } from 'react'
import { getAlerts, type AlertRow, type ListAlertsParams } from '../api'

/**
 * The real alert feed: one row per Alert record, from GET /alerts (see
 * backend/app/api/routes_alerts.py for why that is a dedicated endpoint
 * rather than GET /events?alert_only=true, which intentionally collapses
 * an event matched by two rules down to one row).
 *
 * `kind: 'detection'` restricts to rule + sequence detections; `kind: 'ml'`
 * to ML anomaly records. Every count presented as "alerts" should use
 * 'detection' -- an anomaly is not a detection.
 *
 * Manages its own page state, so a call site that only wants a whole-feed
 * total (`useAlerts({ limit: 1, severity: 'critical' })`) and one that wants
 * a paginated table both work from the same hook.
 */
export function useAlerts(params: Omit<ListAlertsParams, 'limit' | 'offset'> & { limit?: number } = {}, pollMs = 0) {
  const [page, setPage] = useState(0)
  const [alerts, setAlerts] = useState<AlertRow[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [generation, setGeneration] = useState(0)

  const refresh = useCallback(() => setGeneration((g) => g + 1), [])

  const { host, start_date, end_date, q, severity, kind, limit = 50 } = params

  // Reset to page 0 when the filters change -- during render, not in an
  // effect, so the load below never fires once with the stale page offset.
  const filterKey = JSON.stringify([host, start_date, end_date, q, severity, kind, limit])
  const [appliedKey, setAppliedKey] = useState(filterKey)
  if (appliedKey !== filterKey) {
    setAppliedKey(filterKey)
    setPage(0)
  }
  const effectivePage = appliedKey === filterKey ? page : 0

  useEffect(() => {
    let cancelled = false

    async function load(showSpinner: boolean) {
      if (showSpinner) setLoading(true)
      try {
        const response = await getAlerts({
          host,
          start_date,
          end_date,
          q,
          severity,
          kind,
          limit,
          offset: effectivePage * limit,
        })
        if (cancelled) return
        setAlerts(response.alerts)
        setTotal(response.total)
        setError(null)
      } catch (err) {
        if (!cancelled) setError((err as Error).message)
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    void load(true)

    // Background refreshes deliberately skip the spinner: a live feed that
    // flashes a skeleton every poll is unreadable.
    const timer = pollMs > 0 ? window.setInterval(() => void load(false), pollMs) : undefined
    return () => {
      cancelled = true
      if (timer) window.clearInterval(timer)
    }
  }, [host, start_date, end_date, q, severity, kind, limit, effectivePage, pollMs, generation])

  return { alerts, total, page: effectivePage, setPage, loading, error, refresh }
}
