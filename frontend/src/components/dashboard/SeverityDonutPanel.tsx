import { PieChart } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import type { IncidentSummary } from '../../api'
import { severityDistribution } from '../../lib/aggregations'
import { SEVERITY_HEX, severityLabel } from '../../lib/severity'
import { Card, Donut, EmptyState } from '../ui'

const DISPLAY_ORDER = ['critical', 'high', 'medium', 'low'] as const

/** Incidents by severity. Clicking a slice filters the incidents list by
 *  that severity, so the chart is a control, not just a picture. */
export function SeverityDonutPanel({ incidents }: { incidents: IncidentSummary[] }) {
  const navigate = useNavigate()
  const distribution = severityDistribution(incidents)

  const slices = DISPLAY_ORDER.filter((severity) => distribution[severity] > 0).map((severity) => ({
    name: severityLabel(severity),
    value: distribution[severity],
    color: SEVERITY_HEX[severity],
    severity,
  }))

  return (
    <Card title="Incidents by severity" icon={<PieChart className="h-3.5 w-3.5" />} accent="blue">
      {slices.length === 0 ? (
        <EmptyState message="No incidents to break down yet" />
      ) : (
        <Donut
          slices={slices}
          total={incidents.length}
          totalLabel="Total"
          height={188}
          onSliceClick={(slice) => {
            const match = slices.find((s) => s.name === slice.name)
            if (match) navigate(`/incidents?severity=${match.severity}`)
          }}
        />
      )}
    </Card>
  )
}
