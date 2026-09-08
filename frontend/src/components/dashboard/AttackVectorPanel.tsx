import { Crosshair } from 'lucide-react'
import type { IncidentSummary, MitreTechnique } from '../../api'
import { attackVectorBreakdown } from '../../lib/aggregations'
import { CATEGORICAL, CATEGORICAL_OTHER } from '../../lib/tokens'
import { Card, Donut, EmptyState } from '../ui'

/**
 * Primary attack vector share by MITRE tactic. Attribution is the first
 * tactic of the first technique on each incident (stated in the subtitle so
 * the number is interpretable); incidents with no resolvable technique are
 * excluded from the denominator rather than being folded into "Other".
 */
export function AttackVectorPanel({
  incidents,
  techniqueById,
}: {
  incidents: IncidentSummary[]
  techniqueById: Map<string, MitreTechnique>
}) {
  const breakdown = attackVectorBreakdown(incidents, techniqueById)

  const slices = breakdown.map((slice, index) => ({
    name: slice.label,
    value: slice.count,
    color: slice.tactic === 'other' ? CATEGORICAL_OTHER : CATEGORICAL[index % CATEGORICAL.length],
  }))

  return (
    <Card
      title="Top attack vectors"
      subtitle="By MITRE tactic"
      icon={<Crosshair className="h-3.5 w-3.5" />}
      accent="violet"
      bodyClassName="flex items-center justify-center"
    >
      {slices.length === 0 ? (
        <EmptyState message="No techniques attributed yet" />
      ) : (
        <Donut slices={slices} totalLabel="Attributed" height={176} />
      )}
    </Card>
  )
}
