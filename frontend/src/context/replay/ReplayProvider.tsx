import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import {
  ApiError,
  getDemoScenarios,
  getReplayStatus,
  resetDemoData,
  startReplay,
  stopReplay,
  type ReplayStatusResponse,
  type ScenarioInfo,
} from '../../api'
import { REPLAY_STATUS_POLL_MS } from '../../lib/constants'
import { clearSeenIncidentIds } from '../../hooks/useUnseenIncidents'
import { useIncidentsSnapshot } from '../incidents/useIncidentsSnapshot'
import { ReplayContext } from './ReplayContext'

/**
 * The live-replay demo: server-driven, this provider is only a viewport
 * onto it. On mount it fetches status unconditionally (not just when a run
 * was started from this tab), so reloading the page -- or opening a second
 * tab -- reattaches to a replay the backend is already running rather than
 * assuming nothing is happening. It then polls only while `state ===
 * 'running'`, so an idle console costs zero extra requests.
 *
 * Each incident the run reports gets folded into a refresh of the shared
 * incidents snapshot as soon as it appears, rather than waiting out that
 * context's own 30s poll -- this is what makes the console visibly react
 * within a couple of seconds of an incident forming during a demo.
 */
export function ReplayProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<ReplayStatusResponse | null>(null)
  const [scenarios, setScenarios] = useState<ScenarioInfo[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const { refresh: refreshIncidents } = useIncidentsSnapshot()
  const seenIncidentCount = useRef(0)

  const applyStatus = useCallback(
    (next: ReplayStatusResponse) => {
      setStatus(next)
      if (next.incident_ids.length > seenIncidentCount.current) {
        seenIncidentCount.current = next.incident_ids.length
        refreshIncidents()
      }
      if (next.state !== 'running') {
        // A finished/stopped/failed run means no more incidents are coming
        // from it; the next start() resets this so a fresh run's first
        // incident is still treated as new.
        seenIncidentCount.current = next.incident_ids.length
      }
    },
    [refreshIncidents],
  )

  useEffect(() => {
    let cancelled = false

    getDemoScenarios()
      .then((response) => {
        if (!cancelled) setScenarios(response.scenarios)
      })
      .catch(() => {
        // Scenario listing is supporting context for the Start control, not
        // something worth a full-page error over.
      })

    getReplayStatus()
      .then((response) => {
        if (cancelled) return
        seenIncidentCount.current = response.incident_ids.length
        applyStatus(response)
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
    // eslint-disable-next-line react-hooks/exhaustive-deps -- runs once on mount only
  }, [])

  useEffect(() => {
    if (status?.state !== 'running') return

    const timer = window.setInterval(() => {
      getReplayStatus()
        .then((response) => {
          applyStatus(response)
          setError(null)
        })
        .catch((err: Error) => setError(err.message))
    }, REPLAY_STATUS_POLL_MS)

    return () => window.clearInterval(timer)
  }, [status?.state, applyStatus])

  const start = useCallback(
    async (scenarioId: string) => {
      seenIncidentCount.current = 0
      setError(null)
      try {
        const response = await startReplay(scenarioId, true)
        applyStatus(response)
      } catch (err) {
        setError(err instanceof ApiError ? err.detail : 'Failed to start replay')
        throw err
      }
    },
    [applyStatus],
  )

  const stop = useCallback(async () => {
    try {
      const response = await stopReplay()
      applyStatus(response)
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : 'Failed to stop replay')
      throw err
    }
  }, [applyStatus])

  const reset = useCallback(async () => {
    await resetDemoData()
    seenIncidentCount.current = 0
    // A reset restarts the backend's identity sequences, so the next run's
    // incidents reuse ids this browser may already have marked seen.
    clearSeenIncidentIds()
    const response = await getReplayStatus()
    applyStatus(response)
    refreshIncidents()
  }, [applyStatus, refreshIncidents])

  const value = useMemo(
    () => ({
      status,
      state: status?.state ?? 'idle',
      scenarios,
      loading,
      error,
      start,
      stop,
      reset,
    }),
    [status, scenarios, loading, error, start, stop, reset],
  )

  return <ReplayContext.Provider value={value}>{children}</ReplayContext.Provider>
}
