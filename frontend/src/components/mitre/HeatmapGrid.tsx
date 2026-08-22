import type { IncidentSummary, MitreTechnique } from '../../api'
import { tacticTechniqueMatrix } from '../../lib/aggregations'
import { TACTIC_LABELS, TACTIC_ORDER } from '../../lib/tactics'
import { EmptyState } from '../ui'

export function HeatmapGrid({
  incidents,
  techniqueById,
}: {
  incidents: IncidentSummary[]
  techniqueById: Map<string, MitreTechnique>
}) {
  const { cells, tacticsPresent, maxCount } = tacticTechniqueMatrix(incidents, techniqueById)

  if (cells.length === 0) {
    return <EmptyState message="No MITRE technique hits yet -- ingest logs to populate the heatmap" />
  }

  const orderedTactics = TACTIC_ORDER.filter((tactic) => tacticsPresent.includes(tactic))

  return (
    <div className="overflow-x-auto">
      <div className="flex gap-3">
        {orderedTactics.map((tactic) => {
          const tacticCells = cells.filter((c) => c.tactic === tactic).sort((a, b) => b.count - a.count)
          return (
            <div key={tactic} className="flex w-32 shrink-0 flex-col gap-1">
              <div className="mb-1 flex h-10 items-center justify-center text-center text-[10px] font-semibold tracking-wide text-text-muted uppercase">
                {TACTIC_LABELS[tactic]}
              </div>
              {tacticCells.map((cell) => {
                const intensity = 0.15 + 0.85 * (cell.count / maxCount)
                return (
                  <div
                    key={`${tactic}-${cell.techniqueId}`}
                    title={`${cell.techniqueId} -- ${cell.techniqueName} (${cell.count} hit${cell.count === 1 ? '' : 's'})`}
                    className="flex h-9 items-center justify-center rounded border border-accent-cyan/20 text-[11px] font-medium text-text"
                    style={{ backgroundColor: `rgba(34, 211, 238, ${intensity})` }}
                  >
                    {cell.techniqueId}
                  </div>
                )
              })}
            </div>
          )
        })}
      </div>
    </div>
  )
}
