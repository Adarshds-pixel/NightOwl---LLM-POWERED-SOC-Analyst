import { AlertTriangle, Database, Play, RotateCcw, Square } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useReplay } from '../../context/replay/useReplay'
import { useToast } from '../../context/toast/useToast'
import { DEFAULT_DEMO_SCENARIO_ID } from '../../lib/constants'
import { incidentRef } from '../../lib/format'
import { ACCENT } from '../../lib/tokens'
import { Badge, Button, Card, EmptyState, MeterBar, MiniStat, Modal, StatusDot } from '../ui'

const STATE_TONE = {
  idle: 'idle',
  running: 'good',
  finished: 'good',
  stopped: 'warn',
  failed: 'bad',
} as const

/**
 * Live SOC replay control.
 *
 * Every number here comes straight off `GET /demo/replay/status` -- this
 * component renders server state, it does not simulate anything client
 * side. The provenance line under each segment is likewise served by the
 * backend (`GET /demo/scenarios`), not hand-typed here, so it cannot drift
 * from what the replay actually reads.
 */
export function ReplayControlCard() {
  const { status, state, scenarios, error, start, stop, reset } = useReplay()
  const { push } = useToast()
  const [starting, setStarting] = useState(false)
  const [stopping, setStopping] = useState(false)
  const [resetting, setResetting] = useState(false)
  const [confirmResetOpen, setConfirmResetOpen] = useState(false)

  const scenario = scenarios.find((s) => s.id === (status?.scenario_id ?? DEFAULT_DEMO_SCENARIO_ID)) ?? scenarios[0]

  async function handleStart() {
    setStarting(true)
    try {
      await start(scenario?.id ?? DEFAULT_DEMO_SCENARIO_ID)
      push({ tone: 'success', title: 'Replay started', description: 'Telemetry will begin arriving within seconds.' })
    } catch {
      // Error surfaced via context.error below; nothing further to do here.
    } finally {
      setStarting(false)
    }
  }

  async function handleStop() {
    setStopping(true)
    try {
      await stop()
    } finally {
      setStopping(false)
    }
  }

  async function handleReset() {
    setConfirmResetOpen(false)
    setResetting(true)
    try {
      const result = await reset()
      void result
      push({ tone: 'success', title: 'Demo data cleared', description: 'Every event, alert and incident was removed.' })
    } catch {
      push({ tone: 'error', title: 'Reset failed' })
    } finally {
      setResetting(false)
    }
  }

  const running = state === 'running'
  const progressPercent = status && status.duration_seconds > 0 ? (status.elapsed_seconds / status.duration_seconds) * 100 : 0

  return (
    <Card
      title="Live SOC replay"
      subtitle="Real captured telemetry, paced onto the last few hours"
      icon={<Database className="h-3.5 w-3.5" />}
      accent="cyan"
      action={
        <Badge accent={STATE_TONE[state] === 'bad' ? 'red' : state === 'idle' ? 'neutral' : 'cyan'} dot>
          <StatusDot tone={STATE_TONE[state]} pulse={running} className="mr-1" />
          {state}
        </Badge>
      }
    >
      {!scenario ? (
        <EmptyState message="No demo scenarios available" hint="Run backend/scripts/build_demo_scenarios.py to generate one." />
      ) : (
        <div className="flex flex-col gap-4">
          <div>
            <p className="text-body text-text-dim">{scenario.title}</p>
            <p className="mt-1 text-meta text-text-faint">{scenario.description}</p>
          </div>

          <div>
            <div className="flex items-center justify-between text-micro text-text-faint">
              <span>
                {status?.current_segment_id ? `Current: ${status.current_segment_id}` : 'Not running'}
              </span>
              <span className="font-mono tabular-nums">
                {status ? `${Math.round(status.elapsed_seconds)}s / ${Math.round(status.duration_seconds)}s` : '--'}
              </span>
            </div>
            <MeterBar className="mt-1.5" value={progressPercent} max={100} color={ACCENT.cyan} />
          </div>

          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            <MiniStat label="Records" value={`${status?.records_emitted ?? 0} / ${status?.records_total ?? 0}`} />
            <MiniStat label="Events ingested" value={status?.events_ingested ?? 0} />
            <MiniStat label="Alerts raised" value={status?.alerts_created ?? 0} />
            <MiniStat label="Incidents formed" value={status?.incident_ids.length ?? 0} />
          </div>

          {status && status.incident_ids.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {status.incident_ids.map((id) => (
                <Link key={id} to={`/incidents/${id}`}>
                  <Badge accent="blue">{incidentRef(id)}</Badge>
                </Link>
              ))}
            </div>
          )}

          {state === 'failed' && status?.error && (
            <div className="flex items-start gap-2 rounded-control border border-accent-red/30 bg-accent-red/10 px-3 py-2 text-meta text-accent-red">
              <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              {status.error}
            </div>
          )}
          {error && <p className="text-meta text-accent-red">{error}</p>}

          <div className="flex flex-wrap items-center gap-2">
            {running ? (
              <Button variant="danger" onClick={handleStop} disabled={stopping} icon={<Square className="h-3.5 w-3.5" />}>
                {stopping ? 'Stopping...' : 'Stop replay'}
              </Button>
            ) : (
              <Button variant="primary" onClick={handleStart} disabled={starting} icon={<Play className="h-3.5 w-3.5" />}>
                {starting ? 'Starting...' : state === 'idle' ? 'Start replay' : 'Run again'}
              </Button>
            )}
            <Button
              variant="secondary"
              onClick={() => setConfirmResetOpen(true)}
              disabled={running || resetting}
              icon={<RotateCcw className="h-3.5 w-3.5" />}
            >
              Reset demo data
            </Button>
          </div>

          <div className="border-t border-line-soft pt-3">
            <p className="mb-1.5 text-micro font-semibold tracking-[0.1em] text-text-faint uppercase">Segment provenance</p>
            <ul className="flex flex-col gap-1">
              {scenario.segments.map((segment) => (
                <li key={segment.id} className="flex items-center justify-between gap-3 text-micro text-text-muted">
                  <span className="truncate">
                    <span className="text-text-dim">{segment.title}</span> - {segment.record_count.toLocaleString()} records
                    from {segment.source_capture}
                  </span>
                  {segment.kind === 'noise' ? (
                    <Badge accent="green">0 matches</Badge>
                  ) : (
                    <Badge accent="amber">{segment.expected_technique_ids.length} techniques</Badge>
                  )}
                </li>
              ))}
            </ul>
            <p className="mt-2 text-micro text-text-faint">
              Every record is copied verbatim from a real Sysmon capture; only the timestamp is rewritten to place it
              on the current shift.
            </p>
          </div>
        </div>
      )}

      <Modal open={confirmResetOpen} onClose={() => setConfirmResetOpen(false)} title="Reset demo data">
        <div className="flex flex-col gap-4 p-5">
          <p className="text-body text-text-dim">
            This permanently deletes every event, alert, incident, chat message and audit entry currently in the
            database. This cannot be undone.
          </p>
          <div className="flex justify-end gap-2">
            <Button variant="ghost" onClick={() => setConfirmResetOpen(false)}>
              Cancel
            </Button>
            <Button variant="danger" onClick={handleReset} icon={<RotateCcw className="h-3.5 w-3.5" />}>
              Delete everything
            </Button>
          </div>
        </div>
      </Modal>
    </Card>
  )
}
