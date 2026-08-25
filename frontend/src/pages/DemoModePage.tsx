import clsx from 'clsx'
import { Link } from 'react-router-dom'
import { DemoTerminal } from '../components/demo/DemoTerminal'
import { EmptyState, MiniStat, Panel } from '../components/ui'
import { type DemoStageId, useDemoMode } from '../hooks/useDemoMode'
import { DEMO_CHAT_QUESTION } from '../lib/constants'

const STAGES: { id: DemoStageId; label: string }[] = [
  { id: 'ingest', label: 'Ingest' },
  { id: 'resolve', label: 'Resolve' },
  { id: 'explain', label: 'Explain' },
  { id: 'chat', label: 'Chat' },
]

function StageDot({ stageId, currentStage, status }: { stageId: DemoStageId; currentStage: DemoStageId | null; status: string }) {
  const stageIndex = STAGES.findIndex((s) => s.id === stageId)
  const currentIndex = currentStage ? STAGES.findIndex((s) => s.id === currentStage) : -1

  let tone = 'bg-border'
  if (status === 'error' && stageIndex === currentIndex) tone = 'bg-accent-red'
  else if (stageIndex < currentIndex || status === 'success') tone = 'bg-accent-green'
  else if (stageIndex === currentIndex && status === 'running') tone = 'bg-accent-cyan animate-pulse'

  return <span className={clsx('h-2.5 w-2.5 rounded-full', tone)} />
}

function DemoModePage() {
  const { status, currentStage, log, ingestResult, explainResult, chatResult, primaryIncidentId, run, reset } =
    useDemoMode()

  const running = status === 'running'

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-text">Demo Mode</h1>
        <p className="mt-1 text-sm text-text-muted">
          Runs the real ingest &rarr; incident &rarr; explain &rarr; chat pipeline end to end against a
          bundled Sysmon fixture -- every step below is a real backend call, not a scripted animation.
        </p>
      </div>

      <Panel title="Run" accent="cyan">
        <div className="flex flex-wrap items-center gap-6">
          <button
            type="button"
            onClick={run}
            disabled={running}
            className="rounded border border-accent-cyan bg-accent-cyan/10 px-4 py-2 text-sm font-semibold tracking-widest text-accent-cyan uppercase disabled:opacity-50"
          >
            {running ? 'Running...' : status === 'idle' ? 'Run Demo' : 'Run Again'}
          </button>

          <div className="flex items-center gap-4">
            {STAGES.map((stage) => (
              <div key={stage.id} className="flex items-center gap-2">
                <StageDot stageId={stage.id} currentStage={currentStage} status={status} />
                <span className="text-xs tracking-widest text-text-muted uppercase">{stage.label}</span>
              </div>
            ))}
          </div>

          {status !== 'idle' && (
            <button type="button" onClick={reset} disabled={running} className="text-xs text-text-muted hover:text-accent-cyan disabled:opacity-50">
              Reset
            </button>
          )}
        </div>
      </Panel>

      <DemoTerminal log={log} />

      {status === 'idle' && log.length === 0 && (
        <Panel accent="neutral">
          <EmptyState message="Click Run Demo to start" />
        </Panel>
      )}

      {status === 'success' && ingestResult && (
        <Panel title="Results" accent="green">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <MiniStat label="Events Ingested" value={ingestResult.events_ingested} accent="cyan" />
            <MiniStat label="Rule Matches" value={ingestResult.rule_matches} accent="amber" />
            <MiniStat label="Alerts Created" value={ingestResult.alerts_created} accent="red" />
            <MiniStat label="Incidents Involved" value={ingestResult.incident_ids.length} accent="purple" />
          </div>

          {explainResult && (
            <div className="mt-4">
              <span className="text-xs font-semibold tracking-widest text-text-muted uppercase">AI Explanation</span>
              <p className="mt-1 line-clamp-4 text-sm whitespace-pre-wrap text-text">{explainResult.explanation}</p>
            </div>
          )}

          {chatResult && (
            <div className="mt-4 space-y-1">
              <span className="text-xs font-semibold tracking-widest text-text-muted uppercase">Demo Chat</span>
              <p className="text-sm text-text-muted">
                <span className="text-text">Q:</span> {DEMO_CHAT_QUESTION}
              </p>
              <p className="text-sm text-text">
                <span className="text-text-muted">A:</span> {chatResult.content}
              </p>
            </div>
          )}

          {primaryIncidentId && (
            <Link
              to={`/incidents/${primaryIncidentId}`}
              className="mt-4 inline-block rounded border border-accent-cyan px-3 py-2 text-xs font-semibold tracking-widest text-accent-cyan uppercase hover:bg-accent-cyan/10"
            >
              Open Full Incident &rarr;
            </Link>
          )}
        </Panel>
      )}
    </div>
  )
}

export default DemoModePage
