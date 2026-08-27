import clsx from 'clsx'
import { Play, RotateCcw, TerminalSquare } from 'lucide-react'
import { Link } from 'react-router-dom'
import { DemoTerminal } from '../components/demo/DemoTerminal'
import { Button, Card, EmptyState, MiniStat, PageHeader } from '../components/ui'
import { type DemoStageId, useDemoMode } from '../hooks/useDemoMode'
import { DEMO_CHAT_QUESTION } from '../lib/constants'

const STAGES: { id: DemoStageId; label: string }[] = [
  { id: 'ingest', label: 'Ingest' },
  { id: 'resolve', label: 'Resolve' },
  { id: 'explain', label: 'Explain' },
  { id: 'chat', label: 'Chat' },
]

function StageDot({
  stageId,
  currentStage,
  status,
}: {
  stageId: DemoStageId
  currentStage: DemoStageId | null
  status: string
}) {
  const stageIndex = STAGES.findIndex((stage) => stage.id === stageId)
  const currentIndex = currentStage ? STAGES.findIndex((stage) => stage.id === currentStage) : -1

  let tone = 'bg-line-strong'
  if (status === 'error' && stageIndex === currentIndex) tone = 'bg-accent-red'
  else if (stageIndex < currentIndex || status === 'success') tone = 'bg-accent-green'
  else if (stageIndex === currentIndex && status === 'running') tone = 'bg-accent-cyan animate-pulse-dot'

  return <span className={clsx('h-2.5 w-2.5 rounded-full', tone)} />
}

/**
 * Demo Mode runs the real pipeline end to end against a bundled Sysmon
 * fixture: the file is uploaded through POST /ingest, detection runs
 * server-side, and the explanation and chat answer come from real LLM
 * calls. Nothing here is a scripted animation.
 */
function DemoModePage() {
  const { status, currentStage, log, ingestResult, explainResult, chatResult, primaryIncidentId, run, reset } =
    useDemoMode()
  const running = status === 'running'

  return (
    <div className="flex flex-col gap-4 p-5">
      <PageHeader
        title="Demo Mode"
        subtitle="Ingest, detect, explain and chat -- every step is a real backend call against a bundled fixture."
        icon={<TerminalSquare className="h-5 w-5 text-accent-cyan" />}
        breadcrumbs={[{ label: 'Overview', to: '/' }, { label: 'Demo Mode' }]}
      />

      <Card title="Pipeline run" accent="cyan">
        <div className="flex flex-wrap items-center gap-6">
          <Button variant="primary" onClick={run} disabled={running} icon={<Play className="h-3.5 w-3.5" />}>
            {running ? 'Running...' : status === 'idle' ? 'Run demo' : 'Run again'}
          </Button>

          <div className="flex flex-wrap items-center gap-4">
            {STAGES.map((stage) => (
              <div key={stage.id} className="flex items-center gap-2">
                <StageDot stageId={stage.id} currentStage={currentStage} status={status} />
                <span className="text-micro tracking-[0.12em] text-text-muted uppercase">{stage.label}</span>
              </div>
            ))}
          </div>

          {status !== 'idle' && (
            <Button variant="ghost" size="sm" onClick={reset} disabled={running} icon={<RotateCcw className="h-3.5 w-3.5" />}>
              Reset
            </Button>
          )}
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
        <Card title="Results" accent="green">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <MiniStat label="Events ingested" value={ingestResult.events_ingested.toLocaleString()} />
            <MiniStat label="Rule matches" value={ingestResult.rule_matches} />
            <MiniStat label="Alerts created" value={ingestResult.alerts_created} />
            <MiniStat label="Incidents involved" value={ingestResult.incident_ids.length} />
          </div>

          {explainResult && (
            <div className="mt-4">
              <p className="text-micro font-semibold tracking-[0.12em] text-text-faint uppercase">AI explanation</p>
              <p className="mt-1 line-clamp-4 text-body text-text-dim">
                {explainResult.explanation.replace(/[#*`]/g, '').trim()}
              </p>
            </div>
          )}

          {chatResult && (
            <div className="mt-4 flex flex-col gap-1">
              <p className="text-micro font-semibold tracking-[0.12em] text-text-faint uppercase">Demo chat</p>
              <p className="text-meta text-text-muted">
                <span className="text-text">Q:</span> {DEMO_CHAT_QUESTION}
              </p>
              <p className="text-body text-text-dim">
                <span className="text-text-muted">A:</span> {chatResult.content}
              </p>
            </div>
          )}

          {primaryIncidentId && (
            <Link
              to={`/incidents/${primaryIncidentId}`}
              className="mt-4 inline-flex items-center gap-1 text-meta font-semibold tracking-wide text-accent-cyan uppercase"
            >
              Open the full incident
            </Link>
          )}
        </Card>
      )}
    </div>
  )
}

export default DemoModePage
