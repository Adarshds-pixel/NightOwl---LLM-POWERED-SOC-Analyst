import { useCallback, useRef, useState } from 'react'
import {
  getIncidents,
  ApiError,
  explainIncident,
  fetchDemoFixtureBytes,
  getDemoFixtures,
  ingestEvtxFile,
  postChatMessage,
  type ChatMessageResponse,
  type DemoFixtureInfo,
  type ExplainResponse,
  type IngestResponse,
} from '../api'
import { useIncidentsSnapshot } from '../context/incidents/useIncidentsSnapshot'
import { selectMostActionableIncident } from '../lib/aggregations'
import { DEMO_CHAT_QUESTION, nextDemoFixture } from '../lib/constants'

export type DemoStageId = 'ingest' | 'resolve' | 'explain' | 'chat'
export type DemoRunStatus = 'idle' | 'running' | 'success' | 'error'
export interface DemoLogLine {
  id: string
  text: string
  tone: 'info' | 'success' | 'error'
}

export const DEMO_STAGE_ORDER: DemoStageId[] = ['ingest', 'resolve', 'explain', 'chat']

let logCounter = 0

// Downloads the real fixture's bytes from GET /demo/fixtures/{filename}
// (backend/app/api/routes_demo.py) and wraps them in a real File, so the
// actual upload below goes through the same multipart POST /ingest path a
// human dragging in a file would use -- no mocked ingest response.
async function fetchDemoFixtureFile(fixture: DemoFixtureInfo): Promise<File> {
  const blob = await fetchDemoFixtureBytes(fixture.filename)
  return new File([blob], fixture.filename, { type: 'application/octet-stream' })
}

// Each stage below wraps one real awaited backend call -- unlike
// useExplain.ts's cosmetic stage timer (which narrates sub-steps of a single
// opaque call), Demo Mode genuinely has four sequential real requests, so
// narration only ever advances alongside an actual network round trip.
export function useDemoMode() {
  const { refresh: refreshIncidents } = useIncidentsSnapshot()
  const [status, setStatus] = useState<DemoRunStatus>('idle')
  const [currentStage, setCurrentStage] = useState<DemoStageId | null>(null)
  const [log, setLog] = useState<DemoLogLine[]>([])
  const [ingestResult, setIngestResult] = useState<IngestResponse | null>(null)
  const [explainResult, setExplainResult] = useState<ExplainResponse | null>(null)
  const [chatResult, setChatResult] = useState<ChatMessageResponse | null>(null)
  const [primaryIncidentId, setPrimaryIncidentId] = useState<number | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [activeFixture, setActiveFixture] = useState<DemoFixtureInfo | null>(null)
  // Set only when the fallback branch below fires -- distinct from
  // primaryIncidentId being non-null, since that's also true on the
  // genuine fresh-detection path. The UI (DemoModePage.tsx) uses this to
  // show an explicit banner rather than silently pairing a "0 events
  // ingested" result with an AI explanation of some other, older
  // incident -- a real point of confusion found in manual QA (the fixture
  // pool is now real-world samples this deployment's shared demo database
  // has very likely already ingested at some point, so this path fires
  // far more often than the old small synthetic pool ever did).
  const [fallbackIncident, setFallbackIncident] = useState<{
    id: number
    title: string
    reason: 'already_ingested' | 'no_detection'
  } | null>(null)
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
    setFallbackIncident(null)

    try {
      appendLog('Loading the current detected real-world sample pool...')
      const { fixtures } = await getDemoFixtures()
      if (fixtures.length === 0) {
        appendLog('No detected real-world fixtures available -- run backend/scripts/build_failure_matrix.py.', 'error')
        setError('No detected real-world fixtures available.')
        setStatus('error')
        return
      }
      const fixture = nextDemoFixture(fixtures)
      setActiveFixture(fixture)

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
        // Defensive fallback, not the expected path -- every fixture in the
        // pool is one build_failure_matrix.py itself marked `detected: true`
        // in its own isolated fresh-DB run, so a zero-match result here
        // would mean the shared demo database's accumulated state changed
        // the outcome, not that the fixture is genuinely undetectable.
        // `events_ingested === 0` specifically means every record in this
        // fixture already existed in the DB (ingestion dedupes by content)
        // -- almost certainly why this fires often once a deployment's demo
        // database has been used for a while, since the pool now draws from
        // the same real-world corpus this project's own testing repeatedly
        // uploads. Kept so explain/chat still have real data to run against
        // either way, but the UI (DemoModePage.tsx) must show this plainly
        // via `fallbackIncident` -- silently pairing "0 events" with an AI
        // explanation of some other, older incident reads as broken.
        appendLog(
          ingest.events_ingested === 0
            ? 'Every event in this fixture was already ingested in an earlier run -- nothing new to detect.'
            : 'This fixture triggered no detection rule this run.',
        )
        // Fetched fresh: the snapshot captured when Run was clicked can be
        // empty (first load) or stale, which used to stop the run with "no
        // incident to fall back to" even though incidents existed.
        const fresh = await getIncidents({ limit: 200 })
        const fallback = selectMostActionableIncident(fresh.incidents)
        if (!fallback) {
          appendLog('No existing incident to fall back to either -- stopping before explain/chat.', 'error')
          setStatus('success')
          return
        }
        setFallbackIncident({
          id: fallback.id,
          title: fallback.title,
          reason: ingest.events_ingested === 0 ? 'already_ingested' : 'no_detection',
        })
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
  }, [appendLog, refreshIncidents])

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
    setFallbackIncident(null)
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
    fallbackIncident,
    error,
    run,
    reset,
  }
}
