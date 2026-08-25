import { Link } from 'react-router-dom'
import { useIncidentsSnapshot } from '../../context/incidents/useIncidentsSnapshot'
import { formatRelativeTime } from '../../lib/format'
import { EmptyState, Panel, SeverityBadge } from '../ui'

const FEED_LIMIT = 8

// There is no flat GET /alerts endpoint -- alerts only exist nested inside
// a single incident's detail response. This feed honestly surfaces recent
// *incident* activity (the most granular data actually available
// dashboard-wide) rather than fabricating per-rule alert records; same
// reframe the Day 16 "Threat Matrix" -> HostGraph rename already established.
export function ActiveAlertsFeed() {
  const { incidents } = useIncidentsSnapshot()

  const active = incidents
    .filter((i) => i.status === 'open' || i.status === 'investigating')
    .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
    .slice(0, FEED_LIMIT)

  return (
    <Panel
      title="Active Alerts"
      accent="red"
      action={
        <Link to="/incidents" className="text-xs text-text-muted hover:text-accent-cyan">
          View All
        </Link>
      }
    >
      <p className="mb-3 text-[10px] tracking-widest text-text-muted uppercase">
        Most recent open / investigating incidents
      </p>
      {active.length === 0 ? (
        <EmptyState message="No active alerts -- all clear" />
      ) : (
        <ul className="space-y-2">
          {active.map((incident) => (
            <li key={incident.id} className="flex items-center justify-between gap-3 border-b border-border pb-2 last:border-0">
              <div className="flex items-center gap-3">
                <SeverityBadge severity={incident.severity} />
                <Link to={`/incidents/${incident.id}`} className="text-sm text-text hover:text-accent-cyan">
                  {incident.title}
                </Link>
              </div>
              <div className="flex shrink-0 items-center gap-3 text-xs text-text-muted">
                <span>{incident.host}</span>
                <span>{formatRelativeTime(incident.created_at)}</span>
              </div>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  )
}
