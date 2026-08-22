import type { IncidentSummary, MitreTechnique } from '../../api'
import { AttackVectorDonut } from './AttackVectorDonut'
import { SeverityTrendChart } from './SeverityTrendChart'
import { TacticActivityBars } from './TacticActivityBars'

export function AnalyticsRow({
  incidents,
  techniqueById,
}: {
  incidents: IncidentSummary[]
  techniqueById: Map<string, MitreTechnique>
}) {
  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
      <AttackVectorDonut incidents={incidents} techniqueById={techniqueById} />
      <SeverityTrendChart incidents={incidents} />
      <TacticActivityBars incidents={incidents} techniqueById={techniqueById} />
    </div>
  )
}
