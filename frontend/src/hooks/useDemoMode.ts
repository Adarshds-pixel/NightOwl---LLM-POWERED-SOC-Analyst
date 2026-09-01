import { useCallback, useRef, useState } from 'react'
import {
  ApiError,
  explainIncident,
  ingestEvtxFile,
  postChatMessage,
  type ChatMessageResponse,
  type ExplainResponse,
  type IngestResponse,
} from '../api'
import { useIncidentsSnapshot } from '../context/incidents/useIncidentsSnapshot'
import { selectMostActionableIncident } from '../lib/aggregations'
import { DEMO_CHAT_QUESTION, nextDemoFixture, type DemoFixture } from '../lib/constants'

export type DemoStageId = 'ingest' | 'resolve' | 'explain' | 'chat'
export type DemoRunStatus = 'idle' | 'running' | 'success' | 'error'
export interface DemoLogLine {
  id: string
  text: string
  tone: 'info' | 'success' | 'error'
}

export const DEMO_STAGE_ORDER: DemoStageId[] = ['ingest', 'resolve', 'explain', 'chat']

let logCounter = 0

// Fetches the fixture as a static asset (frontend/public/demo/...) and wraps
// it in a real File, so the actual upload below goes through the same
// multipart POST /ingest path a human dragging in a file would use -- no
// mocked ingest response.
async function fetchDemoFixtureFile(fixture: DemoFixture): Promise<File> {
  const res = await fetch(fixture.url)
  if (!res.ok) throw new Error(`Failed to load demo fixture (${res.status})`)
  const blob = await res.blob()
  return new File([blob], fixture.filename, { type: 'application/octet-stream' })
}

// Each stage below wraps one real awaited backend call -- unlike
// useExplain.ts's cosmetic stage timer (which narrates sub-steps of a single
// opaque call), Demo Mode genuinely has four sequential real requests, so
// narration only ever advances alongside an actual network round trip.
export function useDemoMode() {
  const { incidents, refresh: refreshIncidents } = useIncidentsSnapshot()
  const [status, setStatus] = useState<DemoRunStatus>('idle')
  const [currentStage, setCurrentStage] = useState<DemoStageId | null>(null)
  const [log, setLog] = useState<DemoLogLine[]>([])
  const [ingestResult, setIngestResult] = useState<IngestResponse | null>(null)
  const [explainResult, setExplainResult] = useState<ExplainResponse | null>(null)
  const [chatResult, setChatResult] = useState<ChatMessageResponse | null>(null)
  const [primaryIncidentId, setPrimaryIncidentId] = useState<number | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [activeFixture, setActiveFixture] = useState<DemoFixture | null>(null)
  const runningRef = useRef(false)

  const appendLog = useCallback((text: string, tone: DemoLogLine['tone'] = 'info') => {
    setLog((prev) => [...prev, { id: `log-${++logCounter}`, text, tone }])
  }, [])

  const run = useCallback(async () => {
    if (runningRef.current) return
    runningRef.current = true
    setStatus('running')
    setError(null)
    setLog([])
    setIngestResult(null)
    setExplainResult(null)
    setChatResult(null)
    setPrimaryIncidentId(null)

    const fixture = nextDemoFixture()
    setActiveFixture(fixture)

    try {
      setCurrentStage('ingest')
      appendLog(`Scenario: ${fixture.label}`)
      appendLog(`Fetching ${fixture.filename}...`)
      const file = await fetchDemoFixtureFile(fixture)
      appendLog('Uploading to POST /ingest...')
      const ingest = await ingestEvtxFile(file)
      setIngestResult(ingest)
      appendLog(
        `Ingested ${ingest.events_ingested} events, ${ingest.rule_matches} rule match(es), ` +
          `${ingest.alerts_created} alert(s) created.`,
        'success',
      )
      refreshIncidents()

      setCurrentStage('resolve')
      let targetId: number
      if (ingest.incident_ids.length > 0) {
        // Single-host fixture -- the first (and typically only) incident id
        // is the safe target; reuses the ingest response directly rather
        // than re-polling GET /incidents.
        targetId = ingest.incident_ids[0]
        appendLog(`Resolved incident #${targetId} for the rest of this run.`, 'success')
      } else {
        // Defensive fallback, not the expected path with any pool fixture
        // (each one is individually verified to trip its declared
        // techniques -- see backend/scripts/build_demo_evtx_fixtures.py) --
        // kept in case a future fixture swap or a rule change ever yields
        // zero matches, so explain/chat still have real data to run against.
        appendLog('This fixture triggered no detection rule this run.')
        const fallback = selectMostActionableIncident(incidents)
        if (!fallback) {
          appendLog('No existing incident to fall back to either -- stopping before explain/chat.', 'error')
          setStatus('success')
          return
        }
        targetId = fallback.id
        appendLog(`Continuing with existing incident #${targetId} ("${fallback.title}") instead.`, 'success')
      }
      setPrimaryIncidentId(targetId)

      setCurrentStage('explain')
      appendLog('Requesting AI explanation (retrieve -> draft -> self-critique)...')
      const explain = await explainIncident(targetId)
      setExplainResult(explain)
      appendLog('Explanation received.', 'success')

      setCurrentStage('chat')
      appendLog(`Demo Mode asks (scripted question): "${DEMO_CHAT_QUESTION}"`)
      const chat = await postChatMessage(targetId, DEMO_CHAT_QUESTION)
      setChatResult(chat)
      appendLog('Reply received -- this answer is real, not canned.', 'success')

      setStatus('success')
    } catch (err) {
      const message = err instanceof ApiError ? err.detail : err instanceof Error ? err.message : 'Demo run failed'
      appendLog(message, 'error')
      setError(message)
      setStatus('error')
    } finally {
      runningRef.current = false
    }
  }, [appendLog, refreshIncidents, incidents])

  const reset = useCallback(() => {
    setStatus('idle')
    setCurrentStage(null)
    setLog([])
    setIngestResult(null)
    setExplainResult(null)
    setChatResult(null)
    setPrimaryIncidentId(null)
    setError(null)
    setActiveFixture(null)
  }, [])

  return {
    status,
    currentStage,
    log,
    ingestResult,
    explainResult,
    chatResult,
    primaryIncidentId,
    activeFixture,
    error,
    run,
    reset,
  }
}
