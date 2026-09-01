import { Eye, ShieldAlert } from 'lucide-react'
import { useMemo, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import type { IncidentSummary, Severity } from '../api'
import {
  DEFAULT_INCIDENT_FILTERS,
  IncidentFilters,
  type IncidentFilterState,
} from '../components/incidents/IncidentFilters'
import { LogUploadControl } from '../components/ingest/LogUploadControl'
import {
  Button,
  Card,
  DataTable,
  ErrorState,
  Pagination,
  PageHeader,
  SeverityBadge,
  SkeletonCard,
  StatCard,
  StatusBadge,
  type Column,
  type SortState,
} from '../components/ui'
import { useIncidentsSnapshot } from '../context/incidents/useIncidentsSnapshot'
import { useMitreCatalog } from '../context/mitre/useMitreCatalog'
import { usePreferences } from '../context/preferences/usePreferences'
import { bucketCounts, periodDelta, severityDistribution } from '../lib/aggregations'
import { filterIncidents, primaryTactic } from '../lib/filtering'
import { formatDateTime, incidentRef } from '../lib/format'
import { TACTIC_LABELS, isTactic } from '../lib/tactics'

/**
 * Incident management. The snapshot in context already holds every incident
 * the API returned, so filtering, sorting and paging all happen here in one
 * pass -- which also means the five stat cards and the table can never
 * disagree about what is being looked at.
 */
function IncidentsPage() {
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const { prefs } = usePreferences()
  const { incidents, meta, loading, error, refresh } = useIncidentsSnapshot()
  const { byId } = useMitreCatalog()

  // Deep links from the dashboard (e.g. a severity slice) seed the filters.
  const [filters, setFilters] = useState<IncidentFilterState>(() => ({
    ...DEFAULT_INCIDENT_FILTERS,
    severity: (searchParams.get('severity') as Severity | null) ?? 'all',
    status: searchParams.get('status') ?? 'all',
  }))
  const [sort, setSort] = useState<SortState | null>(null)
  const [page, setPage] = useState(0)
  const [pageSize, setPageSize] = useState(prefs.pageSize)

  const filtered = useMemo(() => filterIncidents(incidents, filters, byId), [incidents, filters, byId])
  const distribution = severityDistribution(incidents)
  const times = incidents.map((incident) => incident.created_at)
  const visible = filtered.slice(page * pageSize, page * pageSize + pageSize)

  const columns: Column<IncidentSummary>[] = [
    {
      key: 'id',
      header: 'Incident',
      sortValue: (incident) => incident.id,
      cell: (incident) => <span className="font-mono text-meta text-text-muted">{incidentRef(incident.id)}</span>,
    },
    {
      key: 'title',
      header: 'Title',
      sortValue: (incident) => incident.title,
      className: 'max-w-[280px]',
      cell: (incident) => <span className="block truncate text-text">{incident.title}</span>,
    },
    {
      key: 'severity',
      header: 'Severity',
      sortValue: (incident) => incident.severity,
      cell: (incident) => <SeverityBadge severity={incident.severity} score={incident.severity_score} />,
    },
    {
      key: 'status',
      header: 'Status',
      sortValue: (incident) => incident.status,
      cell: (incident) => <StatusBadge status={incident.status} />,
    },
    {
      key: 'tactic',
      header: 'Tactic',
      hideBelow: 'lg',
      cell: (incident) => {
        const tactic = primaryTactic(incident, byId)
        return <span className="text-text-muted">{tactic && isTactic(tactic) ? TACTIC_LABELS[tactic] : '--'}</span>
      },
    },
    {
      key: 'technique',
      header: 'Technique',
      hideBelow: 'md',
      cell: (incident) => (
        <span className="font-mono text-meta text-accent-cyan">{incident.mitre_technique_ids[0] ?? '--'}</span>
      ),
    },
    {
      key: 'host',
      header: 'Host',
      sortValue: (incident) => incident.host,
      hideBelow: 'sm',
      cell: (incident) => <span className="font-mono text-meta text-text-muted">{incident.host}</span>,
    },
    {
      key: 'created',
      header: 'Detected',
      sortValue: (incident) => incident.created_at,
      hideBelow: 'md',
      cell: (incident) => (
        <span className="font-mono text-meta whitespace-nowrap text-text-muted">
          {formatDateTime(incident.created_at)}
        </span>
      ),
    },
    {
      key: 'actions',
      header: '',
      align: 'right',
      cell: (incident) => (
        <Button
          variant="icon"
          size="sm"
          aria-label={`Open incident ${incident.id}`}
          onClick={() => navigate(`/incidents/${incident.id}`)}
        >
          <Eye className="h-3.5 w-3.5" />
        </Button>
      ),
    },
  ]

  if (loading) {
    return (
      <div className="grid grid-cols-1 gap-4 p-5 sm:grid-cols-3 xl:grid-cols-5">
        {Array.from({ length: 5 }).map((_, i) => (
          <SkeletonCard key={i} />
        ))}
      </div>
    )
  }

  if (error) return <ErrorState className="py-24" message={error} onRetry={refresh} />

  return (
    <div className="flex flex-col gap-4 p-5">
      <PageHeader
        title="Incidents"
        icon={<ShieldAlert className="h-5 w-5 text-accent-blue" />}
        breadcrumbs={[{ label: 'Overview', to: '/' }, { label: 'Incidents' }]}
        actions={<LogUploadControl onSuccess={refresh} />}
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3 xl:grid-cols-5">
        <StatCard
          label="Total"
          value={meta.totalAll}
          icon={<ShieldAlert className="h-4 w-4" />}
          accent="blue"
          delta={periodDelta(times)}
          trend={bucketCounts(times)}
        />
        <StatCard
          label="Critical"
          value={distribution.critical}
          icon={<ShieldAlert className="h-4 w-4" />}
          accent="red"
          note="Highest severity band"
        />
        <StatCard
          label="High"
          value={distribution.high}
          icon={<ShieldAlert className="h-4 w-4" />}
          accent="amber"
          note="Needs triage today"
        />
        <StatCard
          label="Medium"
          value={distribution.medium}
          icon={<ShieldAlert className="h-4 w-4" />}
          accent="cyan"
          note="Queued for review"
        />
        <StatCard
          label="Low"
          value={distribution.low}
          icon={<ShieldAlert className="h-4 w-4" />}
          accent="green"
          note="Informational baseline"
        />
      </div>

      <IncidentFilters
        filters={filters}
        onChange={(next) => {
          setFilters(next)
          setPage(0)
        }}
      />

      <Card flush divided title={`${filtered.length.toLocaleString()} matching incidents`}>
        <DataTable
          columns={columns}
          rows={visible}
          rowKey={(incident) => incident.id}
          onRowClick={(incident) => navigate(`/incidents/${incident.id}`)}
          sort={sort}
          onSortChange={setSort}
          emptyMessage="No incidents match these filters"
          emptyHint="Try widening the time window or clearing the search."
        />
        <Pagination
          page={page}
          pageSize={pageSize}
          total={filtered.length}
          onPageChange={setPage}
          onPageSizeChange={(size) => {
            setPageSize(size)
            setPage(0)
          }}
          itemLabel="incidents"
        />
      </Card>

      {meta.truncated && (
        <p className="text-micro text-text-faint">
          Showing the {meta.fetchedCount.toLocaleString()} most recent incidents of {meta.totalAll.toLocaleString()};
          older incidents are not loaded into this view.
        </p>
      )}
    </div>
  )
}

export default IncidentsPage
