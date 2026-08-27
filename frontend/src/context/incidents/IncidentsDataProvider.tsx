import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { getIncidents, type IncidentSummary } from '../../api'
import { usePreferences } from '../preferences/usePreferences'
import { backoffMultiplier, countFailure, isDocumentVisible } from '../../lib/polling'
import { INCIDENT_PAGE_SIZE, MAX_INCIDENT_PAGES } from '../../lib/constants'
import { IncidentsDataContext, type IncidentsMeta } from './IncidentsDataContext'

const EMPTY_META: IncidentsMeta = {
  totalAll: 0,
  totalCritical: 0,
  totalOpen: 0,
  totalInvestigating: 0,
  fetchedCount: 0,
  truncated: false,
}

async function fetchAllIncidents(): Promise<{ incidents: IncidentSummary[]; total: number; truncated: boolean }> {
  const first = await getIncidents({ limit: INCIDENT_PAGE_SIZE, offset: 0 })
  const all = [...first.incidents]
  let page = 1
  while (all.length < first.total && page < MAX_INCIDENT_PAGES) {
    const next = await getIncidents({ limit: INCIDENT_PAGE_SIZE, offset: page * INCIDENT_PAGE_SIZE })
    all.push(...next.incidents)
    page++
  }
  return { incidents: all, total: first.total, truncated: all.length < first.total }
}

export function IncidentsDataProvider({ children }: { children: ReactNode }) {
  const { prefs } = usePreferences()
  const [incidents, setIncidents] = useState<IncidentSummary[]>([])
  const [meta, setMeta] = useState<IncidentsMeta>(EMPTY_META)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [generation, setGeneration] = useState(0)
  const loadedOnce = useRef(false)
  // Consecutive 429s, used to back the background poller off (see below).
  const throttleFailures = useRef(0)

  const refresh = useCallback(() => setGeneration((g) => g + 1), [])

  useEffect(() => {
    let cancelled = false
    // Only the first load shows a skeleton; later refreshes (manual or
    // polled) swap the data in place so the page does not flash.
    if (!loadedOnce.current) setLoading(true)
    setError(null)

    Promise.all([
      fetchAllIncidents(),
      getIncidents({ severity: 'critical', limit: 1 }),
      getIncidents({ status: 'open', limit: 1 }),
      getIncidents({ status: 'investigating', limit: 1 }),
    ])
      .then(([bulk, critical, open, investigating]) => {
        if (cancelled) return
        setIncidents(bulk.incidents)
        setMeta({
          totalAll: bulk.total,
          totalCritical: critical.total,
          totalOpen: open.total,
          totalInvestigating: investigating.total,
          fetchedCount: bulk.incidents.length,
          truncated: bulk.truncated,
        })
      })
      .then(() => {
        throttleFailures.current = 0
      })
      .catch((err: Error) => {
        throttleFailures.current = countFailure(err, throttleFailures.current)
        if (!cancelled) setError(err.message)
      })
      .finally(() => {
        if (cancelled) return
        loadedOnce.current = true
        setLoading(false)
      })

    return () => {
      cancelled = true
    }
  }, [generation])

  // Background refresh. The backend has no websocket or SSE, so "live" is
  // a poll at whatever interval the user picked in Settings (0 = off). It
  // reuses the same refresh() the ingest/status flows already call, so a
  // poll and a manual refresh cannot get out of step.
  //
  // This snapshot costs four requests, so it is the most expensive poller in
  // the app: it skips hidden tabs entirely and backs off while the API is
  // throttling, rather than re-spending the budget the visible page needs.
  useEffect(() => {
    if (prefs.refreshIntervalMs <= 0) return

    let ticksSkipped = 0
    const timer = window.setInterval(() => {
      if (!isDocumentVisible()) return
      if (++ticksSkipped < backoffMultiplier(throttleFailures.current)) return
      ticksSkipped = 0
      refresh()
    }, prefs.refreshIntervalMs)

    return () => window.clearInterval(timer)
  }, [prefs.refreshIntervalMs, refresh])

  const value = useMemo(
    () => ({ incidents, meta, loading, error, refresh }),
    [incidents, meta, loading, error, refresh],
  )

  return <IncidentsDataContext.Provider value={value}>{children}</IncidentsDataContext.Provider>
}
