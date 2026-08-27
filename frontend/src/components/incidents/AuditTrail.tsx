import { History } from 'lucide-react'
import { useIncidentAudit } from '../../hooks/useIncidentAudit'
import { formatDateTime, formatRelativeTime } from '../../lib/format'
import { Card, EmptyState, ErrorState, LoadingState, Timeline, TimelineItem } from '../ui'

/**
 * The backend audit log for one incident (GET /incidents/{id}/audit): who
 * changed the status, when, and every explain/chat call recorded against
 * it. This is the real trail, not a UI-side activity guess.
 */
export function AuditTrail({ incidentId }: { incidentId: number }) {
  const { audit, loading, error, refresh } = useIncidentAudit(incidentId)

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
              accentColor="#3b82f6"
            />
          ))}
        </Timeline>
      )}
    </Card>
  )
}
