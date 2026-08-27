import { Bell, Server, ShieldAlert, Siren } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import type { EventLogRow, IncidentSummary } from '../../api'
import type { IncidentsMeta } from '../../context/incidents/IncidentsDataContext'
import { bucketCounts, distinctHosts, periodDelta } from '../../lib/aggregations'
import { StatCard } from '../ui'

/**
 * The four headline metrics. Every figure is a real count from the API and
 * every delta is a genuine 24h-over-24h comparison of ingested timestamps;
 * when there is no previous window to compare against, StatCard says so
 * rather than printing an invented percentage.
 *
 * Note on the fourth tile: the mockup shows "assets monitored", which would
 * imply an asset inventory NightOwl does not have. What it does know
 * exactly is which hosts have produced incidents, so that is what it
 * reports.
 */
export function KpiRow({
  incidents,
  meta,
  alerts,
  alertTotal,
}: {
  incidents: IncidentSummary[]
  meta: IncidentsMeta
  alerts: EventLogRow[]
  alertTotal: number
}) {
  const navigate = useNavigate()

  const incidentTimes = incidents.map((incident) => incident.created_at)
  const criticalTimes = incidents.filter((i) => i.severity === 'critical').map((i) => i.created_at)
  const alertTimes = alerts.map((alert) => alert.timestamp)

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
      <StatCard
        label="Total incidents"
        value={meta.totalAll}
        icon={<ShieldAlert className="h-4 w-4" />}
        accent="blue"
        delta={periodDelta(incidentTimes)}
        trend={bucketCounts(incidentTimes)}
        onClick={() => navigate('/incidents')}
      />
      <StatCard
        label="Critical incidents"
        value={meta.totalCritical}
        icon={<Siren className="h-4 w-4" />}
        accent="red"
        delta={periodDelta(criticalTimes)}
        trend={bucketCounts(criticalTimes)}
        onClick={() => navigate('/incidents?severity=critical')}
      />
      <StatCard
        label="Alerts raised"
        value={alertTotal}
        icon={<Bell className="h-4 w-4" />}
        accent="amber"
        delta={periodDelta(alertTimes)}
        trend={bucketCounts(alertTimes)}
        onClick={() => navigate('/alerts')}
      />
      <StatCard
        label="Hosts affected"
        value={distinctHosts(incidents).length}
        icon={<Server className="h-4 w-4" />}
        accent="green"
        note="Distinct hosts with at least one incident"
        onClick={() => navigate('/incidents')}
      />
    </div>
  )
}
