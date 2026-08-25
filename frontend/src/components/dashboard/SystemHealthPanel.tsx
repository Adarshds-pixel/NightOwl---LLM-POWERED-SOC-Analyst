import { useHealthPing } from '../../hooks/useHealthPing'
import { formatRelativeTime } from '../../lib/format'
import { Panel, StatusPill } from '../ui'

const HEALTH_TONE = {
  healthy: 'good',
  unreachable: 'bad',
  checking: 'neutral',
} as const

const HEALTH_LABEL = {
  healthy: 'API Online',
  unreachable: 'API Unreachable',
  checking: 'Checking...',
} as const

// Small, /health-reachability only -- no fabricated uptime/latency metrics
// the backend doesn't expose. Independent poll instance from Topbar's own
// useHealthPing() call, cheap and self-contained.
export function SystemHealthPanel() {
  const { status, lastCheckedAt } = useHealthPing()

  return (
    <Panel title="System Health" accent="neutral">
      <div className="flex items-center justify-between">
        <StatusPill tone={HEALTH_TONE[status]} label={HEALTH_LABEL[status]} />
        {lastCheckedAt && (
          <span className="text-xs text-text-muted">Checked {formatRelativeTime(lastCheckedAt.toISOString())}</span>
        )}
      </div>
    </Panel>
  )
}
