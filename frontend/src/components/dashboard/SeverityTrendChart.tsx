import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import type { IncidentSummary } from '../../api'
import { bucketizeSeverityTrend } from '../../lib/aggregations'
import { CHART_AXIS_COLOR, CHART_GRID_COLOR, CHART_TOOLTIP_BG, CHART_TOOLTIP_BORDER } from '../../lib/chartTheme'
import { SEVERITY_HEX, SEVERITY_ORDER, severityLabel } from '../../lib/severity'
import { EmptyState, Panel } from '../ui'

export function SeverityTrendChart({ incidents }: { incidents: IncidentSummary[] }) {
  const { points, granularity } = bucketizeSeverityTrend(incidents)
  const data = points.map((p) => ({ label: p.bucketLabel, ...p.counts }))

  return (
    <Panel
      title="Severity Trend"
      accent="cyan"
      action={<span className="text-[10px] text-text-muted uppercase">{granularity}</span>}
    >
      {points.length === 0 ? (
        <EmptyState message="No incidents yet" />
      ) : (
        <ResponsiveContainer width="100%" height={220}>
          <LineChart data={data}>
            <CartesianGrid stroke={CHART_GRID_COLOR} strokeDasharray="3 3" />
            <XAxis dataKey="label" tick={{ fill: CHART_AXIS_COLOR, fontSize: 10 }} stroke={CHART_GRID_COLOR} />
            <YAxis allowDecimals={false} tick={{ fill: CHART_AXIS_COLOR, fontSize: 10 }} stroke={CHART_GRID_COLOR} />
            <Tooltip contentStyle={{ background: CHART_TOOLTIP_BG, border: `1px solid ${CHART_TOOLTIP_BORDER}`, fontSize: 12 }} />
            {SEVERITY_ORDER.map((severity) => (
              <Line
                key={severity}
                type="monotone"
                dataKey={severity}
                name={severityLabel(severity)}
                stroke={SEVERITY_HEX[severity]}
                strokeWidth={2}
                dot={false}
              />
            ))}
          </LineChart>
        </ResponsiveContainer>
      )}
    </Panel>
  )
}
