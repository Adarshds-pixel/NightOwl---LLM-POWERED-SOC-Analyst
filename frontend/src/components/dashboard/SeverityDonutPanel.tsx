import { PieChart } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import type { IncidentsMeta } from '../../context/incidents/IncidentsDataContext'
import { SEVERITY_HEX, severityLabel } from '../../lib/severity'
import { Card, Donut, EmptyState } from '../ui'

const DISPLAY_ORDER = ['critical', 'high', 'medium', 'low'] as const

/** Incidents by severity. Sourced from `meta`'s dedicated ground-truth
 *  per-severity counts (each a real `GET /incidents?severity=X&limit=1`
 *  query), not tallied from the `incidents` array -- that array is capped
 *  at MAX_INCIDENT_PAGES pages (see IncidentsDataProvider.tsx), so a
 *  client-side tally would silently under-count past the cap while this
 *  donut's numbers stay correct regardless of how many incidents exist.
 *  Clicking a slice filters the incidents list by that severity, so the
 *  chart is a control, not just a picture. */
export function SeverityDonutPanel({ meta }: { meta: IncidentsMeta }) {
  const navigate = useNavigate()
  const counts = {
    critical: meta.totalCritical,
    high: meta.totalHigh,
    medium: meta.totalMedium,
    low: meta.totalLow,
  }

  const slices = DISPLAY_ORDER.filter((severity) => counts[severity] > 0).map((severity) => ({
    name: severityLabel(severity),
    value: counts[severity],
    color: SEVERITY_HEX[severity],
    severity,
  }))

  return (
    <Card
      title="Incidents by severity"
      icon={<PieChart className="h-3.5 w-3.5" />}
      accent="primary"
      bodyClassName="flex items-center justify-center"
    >
      {slices.length === 0 ? (
        <EmptyState message="No incidents to break down yet" />
      ) : (
        <Donut
          slices={slices}
          total={meta.totalAll}
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
