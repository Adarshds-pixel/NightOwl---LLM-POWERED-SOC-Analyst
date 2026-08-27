import { RotateCcw } from 'lucide-react'
import type { Severity } from '../../api'
import { FILTERABLE_SEVERITIES, severityLabel } from '../../lib/severity'
import { TACTIC_LABELS, TACTIC_ORDER } from '../../lib/tactics'
import { Button, FilterBar, SearchInput, Select } from '../ui'

export interface IncidentFilterState {
  search: string
  severity: Severity | 'all'
  status: string
  tactic: string
  window: string
}

export const DEFAULT_INCIDENT_FILTERS: IncidentFilterState = {
  search: '',
  severity: 'all',
  status: 'all',
  tactic: 'all',
  window: 'all',
}

export const TIME_WINDOWS = [
  { label: 'All time', value: 'all' },
  { label: 'Last 24 hours', value: '24' },
  { label: 'Last 7 days', value: '168' },
  { label: 'Last 30 days', value: '720' },
]

/** Shared filter strip for the incidents list. Options are built from the
 *  real vocabularies (severity_service severities, backend statuses, MITRE
 *  tactics) rather than hand-typed strings. */
export function IncidentFilters({
  filters,
  onChange,
}: {
  filters: IncidentFilterState
  onChange: (filters: IncidentFilterState) => void
}) {
  const dirty = JSON.stringify(filters) !== JSON.stringify(DEFAULT_INCIDENT_FILTERS)

  return (
    <FilterBar
      search={
        <SearchInput
          value={filters.search}
          onChange={(search) => onChange({ ...filters, search })}
          placeholder="Search incidents by title, host or reference..."
        />
      }
      filters={
        <>
          <Select
            label="Severity"
            value={filters.severity}
            onChange={(severity) => onChange({ ...filters, severity: severity as Severity | 'all' })}
            options={[
              { label: 'All severities', value: 'all' },
              ...FILTERABLE_SEVERITIES.map((severity) => ({ label: severityLabel(severity), value: severity })),
            ]}
            className="w-40"
          />
          <Select
            label="Status"
            value={filters.status}
            onChange={(status) => onChange({ ...filters, status })}
            options={[
              { label: 'All statuses', value: 'all' },
              { label: 'Open', value: 'open' },
              { label: 'Investigating', value: 'investigating' },
              { label: 'Resolved', value: 'resolved' },
              { label: 'Closed', value: 'closed' },
            ]}
            className="w-40"
          />
          <Select
            label="Tactic"
            value={filters.tactic}
            onChange={(tactic) => onChange({ ...filters, tactic })}
            options={[
              { label: 'All tactics', value: 'all' },
              ...TACTIC_ORDER.map((tactic) => ({ label: TACTIC_LABELS[tactic], value: tactic })),
            ]}
            className="w-48"
          />
          <Select
            label="Detected"
            value={filters.window}
            onChange={(window) => onChange({ ...filters, window })}
            options={TIME_WINDOWS}
            className="w-44"
          />
        </>
      }
      actions={
        dirty && (
          <Button size="sm" variant="ghost" onClick={() => onChange(DEFAULT_INCIDENT_FILTERS)} icon={<RotateCcw className="h-3.5 w-3.5" />}>
            Reset
          </Button>
        )
      }
    />
  )
}
