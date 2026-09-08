import { ShieldAlert } from 'lucide-react'
import type { IncidentSummary } from '../../api'
import { formatTimeOfDay, incidentRef } from '../../lib/format'
import { SEVERITY_RANK } from '../../lib/severity'
import { Card, EmptyState, ListRow, SeverityBadge, SeverityDotMarker, ViewAllLink } from '../ui'

/**
 * Open and in-progress incidents, worst first. This is the dashboard queue
 * an analyst works from, so it is ordered by severity then recency rather
 * than by creation time alone.
 */
export function ActiveIncidentsPanel({ incidents }: { incidents: IncidentSummary[] }) {
  const active = incidents
    .filter((incident) => incident.status === 'open' || incident.status === 'investigating')
    .sort((a, b) => {
      const bySeverity = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]
      return bySeverity !== 0 ? bySeverity : b.created_at.localeCompare(a.created_at)
    })

  return (
    <Card
      title="Active incidents"
      icon={<ShieldAlert className="h-3.5 w-3.5" />}
      accent="primary"
      action={<ViewAllLink to="/incidents" />}
      bodyClassName="flex flex-col justify-center px-2 pb-3"
    >
      {active.length === 0 ? (
        <EmptyState message="No active incidents" hint="Everything ingested so far is resolved or closed." />
      ) : (
        <div className="flex flex-col">
          {active.slice(0, 6).map((incident) => (
            <ListRow
              key={incident.id}
              to={`/incidents/${incident.id}`}
              marker={<SeverityDotMarker severity={incident.severity} />}
              title={incident.title}
              meta={`${incidentRef(incident.id)} - ${incident.mitre_technique_ids[0] ?? 'no technique'} - ${incident.host}`}
              trailing={
                <>
                  <span className="hidden font-mono text-micro text-text-faint tabular-nums sm:inline">
                    {formatTimeOfDay(incident.created_at)}
                  </span>
                  <SeverityBadge severity={incident.severity} dot={false} />
                </>
              }
            />
          ))}
        </div>
      )}
    </Card>
  )
}
