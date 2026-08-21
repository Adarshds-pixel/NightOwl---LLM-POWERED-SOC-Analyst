import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'
import { getIncidents, type IncidentSummary } from '../../api'
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
  const [incidents, setIncidents] = useState<IncidentSummary[]>([])
  const [meta, setMeta] = useState<IncidentsMeta>(EMPTY_META)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [generation, setGeneration] = useState(0)

  const refresh = useCallback(() => setGeneration((g) => g + 1), [])

  useEffect(() => {
    let cancelled = false
    setLoading(true)
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

  const value = useMemo(
    () => ({ incidents, meta, loading, error, refresh }),
    [incidents, meta, loading, error, refresh],
  )

  return <IncidentsDataContext.Provider value={value}>{children}</IncidentsDataContext.Provider>
}
