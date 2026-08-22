import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts'
import type { IncidentSummary, MitreTechnique } from '../../api'
import { attackVectorBreakdown } from '../../lib/aggregations'
import { CHART_TOOLTIP_BG, CHART_TOOLTIP_BORDER, TACTIC_PALETTE, TACTIC_PALETTE_OTHER } from '../../lib/chartTheme'
import { EmptyState, Panel } from '../ui'

export function AttackVectorDonut({
  incidents,
  techniqueById,
}: {
  incidents: IncidentSummary[]
  techniqueById: Map<string, MitreTechnique>
}) {
  const slices = attackVectorBreakdown(incidents, techniqueById)
  const total = slices.reduce((sum, s) => sum + s.count, 0)
  const colorFor = (tactic: string, i: number) => (tactic === 'other' ? TACTIC_PALETTE_OTHER : TACTIC_PALETTE[i % TACTIC_PALETTE.length])

  return (
    <Panel title="Attack Vectors" accent="purple">
      {slices.length === 0 ? (
        <EmptyState message="No MITRE-attributed incidents yet" />
      ) : (
        <>
          <div className="relative" style={{ height: 220 }}>
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={slices} dataKey="count" nameKey="label" innerRadius={55} outerRadius={80} paddingAngle={2} stroke="none">
                  {slices.map((slice, i) => (
                    <Cell key={slice.tactic} fill={colorFor(slice.tactic, i)} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ background: CHART_TOOLTIP_BG, border: `1px solid ${CHART_TOOLTIP_BORDER}`, fontSize: 12 }}
                />
              </PieChart>
            </ResponsiveContainer>
            <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
              <span className="font-display text-2xl font-bold text-text">{total}</span>
              <span className="text-[10px] text-text-muted uppercase">Attributed</span>
            </div>
          </div>
          <ul className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-text-muted">
            {slices.map((slice, i) => (
              <li key={slice.tactic} className="flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full" style={{ background: colorFor(slice.tactic, i) }} />
                {slice.label} ({slice.percent.toFixed(0)}%)
              </li>
            ))}
          </ul>
        </>
      )}
    </Panel>
  )
}
