import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import type { IncidentSummary, MitreTechnique } from '../../api'
import { tacticActivityCounts } from '../../lib/aggregations'
import { CHART_AXIS_COLOR, CHART_GRID_COLOR, CHART_TOOLTIP_BG, CHART_TOOLTIP_BORDER } from '../../lib/chartTheme'
import { EmptyState, Panel } from '../ui'

export function TacticActivityBars({
  incidents,
  techniqueById,
}: {
  incidents: IncidentSummary[]
  techniqueById: Map<string, MitreTechnique>
}) {
  const data = tacticActivityCounts(incidents, techniqueById)

  return (
    <Panel title="Tactic Activity" accent="green">
      {data.length === 0 ? (
        <EmptyState message="No technique hits yet" />
      ) : (
        <ResponsiveContainer width="100%" height={Math.max(180, data.length * 32)}>
          <BarChart data={data} layout="vertical" margin={{ left: 24 }}>
            <CartesianGrid stroke={CHART_GRID_COLOR} strokeDasharray="3 3" horizontal={false} />
            <XAxis type="number" allowDecimals={false} tick={{ fill: CHART_AXIS_COLOR, fontSize: 10 }} stroke={CHART_GRID_COLOR} />
            <YAxis type="category" dataKey="label" width={140} tick={{ fill: CHART_AXIS_COLOR, fontSize: 10 }} stroke={CHART_GRID_COLOR} />
            <Tooltip contentStyle={{ background: CHART_TOOLTIP_BG, border: `1px solid ${CHART_TOOLTIP_BORDER}`, fontSize: 12 }} />
            <Bar dataKey="count" fill="#22d3ee" radius={[0, 3, 3, 0]} />
          </BarChart>
        </ResponsiveContainer>
      )}
    </Panel>
  )
}
