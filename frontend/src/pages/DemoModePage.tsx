import { DatabaseZap, Play, RotateCcw, TerminalSquare } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { ApiError, resetDemoData } from '../api'
import { DemoTerminal } from '../components/demo/DemoTerminal'
import { PipelineFlow } from '../components/demo/PipelineFlow'
import { Button, Card, EmptyState, Markdown, MiniStat, Modal, PageHeader } from '../components/ui'
import { useIncidentsSnapshot } from '../context/incidents/useIncidentsSnapshot'
import { useToast } from '../context/toast/useToast'
import { useDemoMode } from '../hooks/useDemoMode'
import { invalidateRulesCache } from '../hooks/useRules'
import { clearSeenIncidentIds } from '../hooks/useUnseenIncidents'
import { DEMO_CHAT_QUESTION } from '../lib/constants'

/**
 * Demo Mode runs the real pipeline end to end against a real-world attack
 * capture: GET /demo/fixtures lists every fixture the current rule set
 * detects (backend/app/api/routes_demo.py, sourced from
 * backend/scripts/build_failure_matrix.py's own output), one is picked
 * without repeating the last one shown, and it's uploaded through POST
 * /ingest -- detection runs server-side, and the explanation and chat
 * answer come from real LLM calls. Nothing here is a scripted animation.
 */
function DemoModePage() {
  const {
    status,
    currentStage,
    log,
    ingestResult,
    explainResult,
    chatResult,
    primaryIncidentId,
    activeFixture,
    fallbackIncident,
    run,
    reset,
  } = useDemoMode()
  const { refresh: refreshIncidents } = useIncidentsSnapshot()
  const { push } = useToast()
  const running = status === 'running'

  const [confirmResetOpen, setConfirmResetOpen] = useState(false)
  const [resettingData, setResettingData] = useState(false)

  async function handleResetData() {
    setConfirmResetOpen(false)
    setResettingData(true)
    try {
      await resetDemoData()
      reset()
      // A reset changes both the incident snapshot and every rule's match
      // count, so the session-cached rule set has to be dropped too -- same
      // reasoning as useLogIngest.ts's upload() -- otherwise Rules Engine,
      // Reports, MITRE and the other useRules() readers keep showing
      // pre-reset counts until something else happens to invalidate it.
      invalidateRulesCache()
      // Incident ids restart at 1 after a reset; without this the bell would
      // treat the new #1-#3 as already seen.
      clearSeenIncidentIds()
      refreshIncidents()
      push({ tone: 'success', title: 'Demo data cleared', description: 'Every event, alert and incident was removed.' })
    } catch (err) {
      push({ tone: 'error', title: 'Reset failed', description: err instanceof ApiError ? err.detail : undefined })
    } finally {
      setResettingData(false)
    }
  }

  return (
    <div className="flex flex-col gap-4 p-5">
      <PageHeader
        title="Demo Mode"
        subtitle="Ingest, detect, explain and chat -- every step is a real backend call, replaying a real attack capture the rules detect."
        icon={<TerminalSquare className="h-5 w-5 text-accent-magenta" />}
        breadcrumbs={[{ label: 'Overview', to: '/' }, { label: 'Demo Mode' }]}
        actions={
          <Button
            variant="secondary"
            onClick={() => setConfirmResetOpen(true)}
            disabled={running || resettingData}
            icon={<DatabaseZap className="h-3.5 w-3.5" />}
          >
            {resettingData ? 'Resetting...' : 'Reset demo data'}
          </Button>
        }
      />

      <Card
        title="Pipeline run"
        subtitle={
          activeFixture ? `Scenario: ${activeFixture.label}` : 'Picks one new real-world attack sample each run'
        }
        accent="magenta"
      >
        <div className="flex flex-wrap items-center gap-4">
          <Button variant="primary" onClick={run} disabled={running} icon={<Play className="h-3.5 w-3.5" />}>
            {running ? 'Running...' : status === 'idle' ? 'Run demo' : 'Run again'}
          </Button>

          {status !== 'idle' && (
            <Button variant="ghost" size="sm" onClick={reset} disabled={running} icon={<RotateCcw className="h-3.5 w-3.5" />}>
              Reset
            </Button>
          )}
        </div>

        <div className="mt-5">
          <PipelineFlow
            status={status}
            currentStage={currentStage}
            ingestResult={ingestResult}
            explainResult={explainResult}
            incidentCount={ingestResult?.incident_ids.length ?? 0}
          />
        </div>

        <div className="mt-4">
          {status === 'idle' && log.length === 0 ? (
            <EmptyState message="Run the demo to watch the real pipeline execute" />
          ) : (
            <DemoTerminal log={log} />
          )}
        </div>
      </Card>

      {status === 'success' && ingestResult && (
        <Card title="Results" accent="primary">
          {fallbackIncident && (
            <p className="mb-3 rounded-control border border-accent-amber/30 bg-accent-amber/10 px-3.5 py-2.5 text-meta text-text-dim">
              {fallbackIncident.reason === 'already_ingested'
                ? "This fixture's events were already ingested in an earlier demo run, so there was nothing new to detect this time (0 across the board below is correct, not broken)."
                : 'This fixture raised no detection in the current database state.'}{' '}
              The AI explanation and chat further down
              continue with an existing incident instead — <strong>{fallbackIncident.title}</strong> — so there's
              still real data to analyze. Click <strong>Reset demo data</strong> above for a clean slate that lets
              every fixture create a fresh incident again.
            </p>
          )}
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <MiniStat label="Events ingested" value={ingestResult.events_ingested.toLocaleString()} />
            <MiniStat label="Rule + sequence matches" value={ingestResult.rule_matches} />
            <MiniStat label="Alerts created" value={ingestResult.alerts_created} />
            <MiniStat label="Incidents involved" value={ingestResult.incident_ids.length} />
          </div>

          {explainResult && (
            <div className="mt-4">
              <p className="text-micro font-semibold tracking-[0.12em] text-text-faint uppercase">AI explanation</p>
              <div className="mt-1 max-h-64 overflow-y-auto rounded-control border border-line-soft bg-surface-2/30 p-3">
                <Markdown content={explainResult.explanation} />
              </div>
            </div>
          )}

          {chatResult && (
            <div className="mt-4 flex flex-col gap-1">
              <p className="text-micro font-semibold tracking-[0.12em] text-text-faint uppercase">Demo chat</p>
              <p className="text-meta text-text-muted">
                <span className="text-text">Q:</span> {DEMO_CHAT_QUESTION}
              </p>
              <div className="max-h-64 overflow-y-auto rounded-control border border-line-soft bg-surface-2/30 p-3">
                <Markdown content={chatResult.content} />
              </div>
            </div>
          )}

          {primaryIncidentId && (
            <Link
              to={`/incidents/${primaryIncidentId}`}
              className="mt-4 inline-flex items-center gap-1 text-meta font-semibold tracking-wide text-accent-magenta uppercase"
            >
              Open the full incident
            </Link>
          )}
        </Card>
      )}

      <Modal open={confirmResetOpen} onClose={() => setConfirmResetOpen(false)} title="Reset demo data">
        <div className="flex flex-col gap-4 p-5">
          <p className="text-body text-text-dim">
            This permanently deletes every event, alert, incident, chat message and audit entry currently in the
            database. This cannot be undone -- use it to start a clean test run rather than piling new uploads onto
            whatever is already there.
          </p>
          <div className="flex justify-end gap-2">
            <Button variant="ghost" onClick={() => setConfirmResetOpen(false)}>
              Cancel
            </Button>
            <Button variant="danger" onClick={handleResetData} icon={<DatabaseZap className="h-3.5 w-3.5" />}>
              Delete everything
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  )
}

export default DemoModePage
