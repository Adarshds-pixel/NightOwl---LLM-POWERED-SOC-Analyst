import type { IncidentSummary } from '../../api'
import { distinctTechniqueCount } from '../../lib/aggregations'
import type { IncidentsMeta } from '../../context/incidents/IncidentsDataContext'
import { KpiCard } from '../ui'

export function KpiRow({ incidents, meta }: { incidents: IncidentSummary[]; meta: IncidentsMeta }) {
  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <KpiCard label="Total Incidents" value={meta.totalAll} accent="cyan" />
      <KpiCard label="Critical Threats" value={meta.totalCritical} accent="red" />
      <KpiCard label="Active Incidents" value={meta.totalOpen + meta.totalInvestigating} accent="amber" />
      <KpiCard label="Techniques Observed" value={distinctTechniqueCount(incidents)} accent="purple" />
    </div>
  )
}
