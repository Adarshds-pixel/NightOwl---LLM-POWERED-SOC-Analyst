import { StatusPill } from '../components/ui'
import { useIncidentsSnapshot } from '../context/incidents/useIncidentsSnapshot'
import { useClock } from '../hooks/useClock'
import { useHealthPing } from '../hooks/useHealthPing'
import { useUnseenIncidents } from '../hooks/useUnseenIncidents'
import { formatClock } from '../lib/format'

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

function Topbar() {
  const { status } = useHealthPing()
  const { incidents } = useIncidentsSnapshot()
  const { unseenCount, markAllSeen } = useUnseenIncidents(incidents)
  const now = useClock()

  return (
    <header className="flex h-14 shrink-0 items-center justify-between border-b border-accent-cyan/20 bg-surface/80 px-6">
      <StatusPill tone={HEALTH_TONE[status]} label={HEALTH_LABEL[status]} />

      <div className="flex items-center gap-5">
        <span className="font-display text-sm tabular-nums text-text-muted">{formatClock(now)}</span>

        <button
          type="button"
          onClick={markAllSeen}
          className="relative flex h-8 w-8 items-center justify-center rounded text-text-muted hover:text-accent-cyan"
          aria-label={`${unseenCount} unseen open incidents`}
        >
          <svg viewBox="0 0 20 20" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={1.5}>
            <path d="M10 2.5c-2.2 0-4 1.8-4 4v2.5c0 1-.4 2-1.1 2.7L4 12.5h12l-.9-.8c-.7-.7-1.1-1.7-1.1-2.7V6.5c0-2.2-1.8-4-4-4Z" />
            <path d="M8.3 15.5a1.7 1.7 0 0 0 3.4 0" strokeLinecap="round" />
          </svg>
          {unseenCount > 0 && (
            <span className="absolute -top-1 -right-1 flex h-4 min-w-4 items-center justify-center rounded-full bg-accent-red px-1 text-[10px] font-bold text-bg">
              {unseenCount}
            </span>
          )}
        </button>
      </div>
    </header>
  )
}

export default Topbar
