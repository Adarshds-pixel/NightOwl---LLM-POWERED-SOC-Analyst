import { useEffect, useRef } from 'react'
import { History } from 'lucide-react'
import { useIncidentAudit } from '../../hooks/useIncidentAudit'
import { formatDateTime, formatRelativeTime } from '../../lib/format'
import { Card, EmptyState, ErrorState, LoadingState, Timeline, TimelineItem } from '../ui'
import { ACCENT } from '../../lib/tokens'

/**
 * The backend audit log for one incident (GET /incidents/{id}/audit): who
 * changed the status, when, and every explain/chat call recorded against
 * it. This is the real trail, not a UI-side activity guess.
 *
 * `refreshSignal` is an optional external trigger (IncidentDetailPage bumps
 * it on every status change): this component owns its own useIncidentAudit
 * instance, and the parent has no other handle into it, so a status change
 * that happens while this tab is already mounted would otherwise only be
 * picked up on the next tab remount. Changing the number re-fetches without
 * touching the initial-mount fetch useIncidentAudit already does on its own.
 */
export function AuditTrail({ incidentId, refreshSignal }: { incidentId: number; refreshSignal?: number }) {
  const { audit, loading, error, refresh } = useIncidentAudit(incidentId)
  const mounted = useRef(false)

  useEffect(() => {
    if (!mounted.current) {
      mounted.current = true
      return
    }
    refresh()
    // eslint-disable-next-line react-hooks/exhaustive-deps -- only re-run on refreshSignal changing, not on refresh identity
  }, [refreshSignal])

  return (
    <Card title="Audit trail" icon={<History className="h-3.5 w-3.5" />} accent="neutral">
      {loading && <LoadingState label="Loading audit trail" />}
      {error && !loading && <ErrorState message={error} onRetry={refresh} />}
      {!loading && !error && audit && audit.count === 0 && (
        <EmptyState message="No audit events yet" hint="Status changes and AI calls are recorded here." />
      )}
      {!loading && !error && audit && audit.count > 0 && (
        <Timeline>
          {audit.events.map((event) => (
            <TimelineItem
              key={event.id}
              title={
                <>
                  <span className="font-medium text-text">{event.action.replace(/_/g, ' ')}</span>
                  <span className="ml-1.5 text-text-muted">by {event.actor}</span>
                </>
              }
              timestamp={formatRelativeTime(event.created_at)}
              detail={
                <span className="flex flex-wrap gap-x-3 gap-y-0.5">
                  {event.details &&
                    Object.entries(event.details).map(([key, value]) => (
                      <span key={key} className="font-mono text-micro">
                        {key}: <span className="text-text-dim">{String(value)}</span>
                      </span>
                    ))}
                  <span className="font-mono text-micro text-text-faint">{formatDateTime(event.created_at)}</span>
                </span>
              }
              accentColor={ACCENT.primary}
            />
          ))}
        </Timeline>
      )}
    </Card>
  )
}
