import { Bell } from 'lucide-react'
import type { AlertRow } from '../../api'
import { formatTimeOfDay } from '../../lib/format'
import { eventMessage } from '../../lib/events'
import { Card, EmptyState, ErrorState, ListRow, SeverityDotMarker, SkeletonRows, ViewAllLink } from '../ui'

/**
 * The newest rule matches -- real alerts, read from GET /alerts, one row
 * per Alert record with the matched rule title and severity the detection
 * engine assigned.
 */
export function RecentAlertsPanel({
  alerts,
  loading,
  error,
  onRetry,
}: {
  alerts: AlertRow[]
  loading: boolean
  error: string | null
  onRetry: () => void
}) {
  return (
    <Card
      title="Recent alerts"
      icon={<Bell className="h-3.5 w-3.5" />}
      accent="amber"
      action={<ViewAllLink to="/alerts" />}
      bodyClassName="px-2 pb-3"
    >
      {loading ? (
        <SkeletonRows rows={5} />
      ) : error ? (
        <ErrorState message={error} onRetry={onRetry} />
      ) : alerts.length === 0 ? (
        <EmptyState message="No alerts raised yet" hint="Alerts appear the moment a detection rule matches an event." />
      ) : (
        <div className="flex flex-col">
          {alerts.slice(0, 6).map((alert) => (
            <ListRow
              key={alert.alert_id}
              to={alert.incident_id ? `/incidents/${alert.incident_id}` : '/alerts'}
              marker={alert.severity ? <SeverityDotMarker severity={alert.severity} /> : undefined}
              title={alert.rule_title ?? eventMessage(alert)}
              meta={`${alert.host} - ${alert.technique_id ?? 'no technique'}`}
              trailing={
                <span className="font-mono text-micro text-text-faint tabular-nums">
                  {formatTimeOfDay(alert.timestamp)}
                </span>
              }
            />
          ))}
        </div>
      )}
    </Card>
  )
}
