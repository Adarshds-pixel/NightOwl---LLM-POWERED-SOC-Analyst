import clsx from 'clsx'
import { Brain, Crosshair, Database, Layers, ShieldAlert, Siren } from 'lucide-react'
import type { ComponentType, ReactNode } from 'react'
import type { ExplainResponse, IngestResponse } from '../../api'
import type { DemoRunStatus, DemoStageId } from '../../hooks/useDemoMode'

/**
 * The detection pipeline, drawn.
 *
 * IMPORTANT -- honesty of the visualisation:
 *
 * Demo Mode makes four real backend calls (`useDemoMode`: ingest -> resolve
 * -> explain -> chat). Detection, correlation and MITRE attribution all
 * happen *server-side inside the single POST /ingest call*; there is no
 * separate request for each, and no backend event stream that would let us
 * light them up one at a time.
 *
 * So the three middle nodes are deliberately drawn as one bracketed group
 * that resolves together the moment the real ingest response lands, and each
 * shows a genuine number from that response (`rule_matches`,
 * `alerts_created`, `matched_rule_titles`). Nothing advances on a timer.
 * This keeps the component consistent with the rule the rest of Demo Mode
 * already follows -- "Nothing here is a scripted animation" -- while still
 * showing the full INGEST -> DETECT -> CORRELATE -> MITRE -> AI -> INCIDENT
 * story the pipeline actually performs.
 */

type NodeState = 'pending' | 'active' | 'done' | 'error'

interface FlowNode {
  id: string
  label: string
  icon: ComponentType<{ className?: string }>
  state: NodeState
  value?: ReactNode
  caption?: string
}

const STATE_RING: Record<NodeState, string> = {
  pending: 'border-line bg-surface-2/50 text-text-faint',
  active: 'border-accent-violet/70 bg-accent-primary/20 text-accent-violet shadow-glow-violet',
  done: 'border-accent-primary/50 bg-accent-primary/12 text-accent-primary',
  error: 'border-accent-red/60 bg-accent-red/15 text-accent-red shadow-glow-red',
}

function stageIndexOf(stage: DemoStageId | null): number {
  if (!stage) return -1
  return ['ingest', 'resolve', 'explain', 'chat'].indexOf(stage)
}

export function PipelineFlow({
  status,
  currentStage,
  ingestResult,
  explainResult,
  incidentCount,
}: {
  status: DemoRunStatus
  currentStage: DemoStageId | null
  ingestResult: IngestResponse | null
  explainResult: ExplainResponse | null
  incidentCount: number
}) {
  const index = stageIndexOf(currentStage)
  const failed = status === 'error'
  const failedAt = failed ? index : -1

  // Everything the ingest call produced becomes known at the same instant.
  const ingested = ingestResult != null
  const serverSideState: NodeState = failed && index === 0 ? 'error' : ingested ? 'done' : index === 0 ? 'active' : 'pending'

  function stateFor(stageIndex: number, complete: boolean): NodeState {
    if (failedAt === stageIndex) return 'error'
    if (complete) return 'done'
    if (index === stageIndex) return 'active'
    return 'pending'
  }

  const nodes: FlowNode[] = [
    {
      id: 'ingest',
      label: 'Ingest',
      icon: Database,
      state: stateFor(0, ingested),
      value: ingestResult ? ingestResult.events_ingested.toLocaleString() : undefined,
      caption: ingestResult ? `of ${ingestResult.records_read.toLocaleString()} records` : 'EVTX upload',
    },
    {
      id: 'detect',
      label: 'Detect',
      icon: ShieldAlert,
      state: serverSideState,
      value: ingestResult ? ingestResult.rule_matches.toLocaleString() : undefined,
      caption: 'Sigma rule matches',
    },
    {
      id: 'correlate',
      label: 'Correlate',
      icon: Layers,
      state: serverSideState,
      value: ingestResult ? ingestResult.alerts_created.toLocaleString() : undefined,
      caption: 'alerts created',
    },
    {
      id: 'mitre',
      label: 'MITRE map',
      icon: Crosshair,
      state: serverSideState,
      value: ingestResult ? ingestResult.matched_rule_titles.length.toLocaleString() : undefined,
      caption: 'rules mapped',
    },
    {
      id: 'ai',
      label: 'AI analysis',
      icon: Brain,
      state: stateFor(2, explainResult != null),
      value: explainResult ? explainResult.sources.length.toLocaleString() : undefined,
      caption: explainResult ? 'sources cited' : 'retrieve, draft, critique',
    },
    {
      id: 'incident',
      label: 'Incident',
      icon: Siren,
      state: failedAt === 3 ? 'error' : status === 'success' ? 'done' : index === 3 ? 'active' : 'pending',
      value: status === 'success' ? incidentCount.toLocaleString() : undefined,
      caption: 'incidents involved',
    },
  ]

  return (
    <div className="grid gap-y-2 sm:grid-cols-6">
      {/* Bracket over the three stages the backend resolves inside the one
          ingest call. It takes a full grid row and repeats the same 6-column
          track inside itself, so it lines up with columns 2-4 exactly rather
          than by eye. */}
      <div className="hidden sm:col-span-6 sm:grid sm:grid-cols-6">
        <div className="col-span-3 col-start-2">
          <p className="mb-1 text-center text-micro tracking-[0.14em] text-text-faint uppercase">
            resolved server-side within the ingest call
          </p>
          <span
            className={clsx(
              'block h-2 rounded-t-md border-t border-r border-l transition-colors duration-300',
              ingested ? 'border-accent-primary/35' : 'border-line-soft',
            )}
          />
        </div>
      </div>

      {nodes.map((node, i) => (
        <div key={node.id} className="relative flex items-center gap-3 sm:flex-col sm:gap-0">
          {/* Track to the next node: starts at this node's centre and spans
              one full column, so it always lands on the next centre. */}
          {i < nodes.length - 1 && (
            <Connector active={node.state === 'done'} pulsing={node.state === 'active'} />
          )}
          <PipelineNode node={node} />
        </div>
      ))}
    </div>
  )
}

function PipelineNode({ node }: { node: FlowNode }) {
  const Icon = node.icon
  const isDone = node.state === 'done'

  return (
    <div className="relative z-10 flex min-w-0 flex-1 items-center gap-3 sm:w-full sm:flex-none sm:flex-col sm:gap-1.5 sm:text-center">
      <span
        className={clsx(
          'relative flex h-11 w-11 shrink-0 items-center justify-center rounded-full border bg-surface-1 transition-all duration-300',
          STATE_RING[node.state],
        )}
      >
        {/* One-shot ring when a stage completes. */}
        {isDone && (
          <span aria-hidden className="absolute inset-0 rounded-full border border-accent-primary/50 animate-ripple" />
        )}
        {node.state === 'active' && (
          <span aria-hidden className="absolute inset-0 rounded-full bg-accent-violet/25 blur-md animate-glow-pulse" />
        )}
        <Icon className="relative h-5 w-5" />
      </span>

      <div className="min-w-0 sm:w-full">
        <p
          className={clsx(
            'truncate text-meta font-semibold tracking-wide transition-colors duration-300',
            node.state === 'pending' ? 'text-text-faint' : 'text-text',
          )}
        >
          {node.label}
        </p>
        {node.value !== undefined ? (
          <p className="font-mono text-title leading-none font-semibold text-text tabular-nums">{node.value}</p>
        ) : (
          <p className="font-mono text-title leading-none font-semibold text-text-faint tabular-nums">--</p>
        )}
        <p className="truncate text-micro text-text-faint">{node.caption}</p>
      </div>
    </div>
  )
}

/**
 * The track between two nodes. Energy travels along it while the stage
 * before it is in flight; it stays lit once that stage has completed.
 *
 * On desktop it is absolutely positioned from this node's centre across one
 * full grid column, so it always terminates on the next node's centre. It
 * sits at z-0 while the node marker sits at z-10, so the line passes behind
 * the circle rather than through it.
 */
function Connector({ active, pulsing }: { active: boolean; pulsing: boolean }) {
  return (
    <span
      aria-hidden
      className={clsx(
        'pointer-events-none absolute overflow-hidden',
        // Mobile: a short vertical stub under the marker.
        'top-11 left-[21px] z-0 h-4 w-px',
        // Desktop: horizontal, from this centre to the next.
        'sm:top-5 sm:left-1/2 sm:h-px sm:w-full',
        active ? 'bg-accent-primary/50' : 'bg-line',
      )}
    >
      {pulsing && (
        <span className="absolute inset-y-0 hidden w-1/4 bg-gradient-to-r from-transparent via-accent-violet to-transparent animate-flow sm:block" />
      )}
    </span>
  )
}
