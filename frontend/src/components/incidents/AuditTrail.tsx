import { useIncidentAudit } from '../../hooks/useIncidentAudit'
import { formatRelativeTime } from '../../lib/format'
import { EmptyState, ErrorState, LoadingState, Panel } from '../ui'

export function AuditTrail({ incidentId }: { incidentId: number }) {
  const { audit, loading, error, refresh } = useIncidentAudit(incidentId)

  return (
    <Panel title="Audit Trail" accent="neutral">
      {loading && <LoadingState label="Loading audit trail" />}
      {error && !loading && <ErrorState message={error} onRetry={refresh} />}
      {!loading && !error && audit && audit.count === 0 && <EmptyState message="No audit events yet" />}
      {!loading && !error && audit && audit.count > 0 && (
        <ul className="space-y-2 text-sm">
          {audit.events.map((event) => (
            <li
              key={event.id}
              className="flex items-start justify-between gap-3 border-b border-border pb-2 last:border-0"
            >
              <div>
                <span className="font-medium text-text">{event.action}</span>
                <span className="ml-2 text-text-muted">by {event.actor}</span>
                {event.details && (
                  <div className="mt-0.5 text-xs text-text-muted">
                    {Object.entries(event.details)
                      .map(([key, value]) => `${key}: ${String(value)}`)
                      .join(' · ')}
                  </div>
                )}
              </div>
              <span className="shrink-0 text-xs text-text-muted">{formatRelativeTime(event.created_at)}</span>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  )
}
