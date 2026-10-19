import { Eye, ShieldAlert } from 'lucide-react'
import { useMemo, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import type { IncidentSummary, IngestResponse, Severity } from '../api'
import {
  DEFAULT_INCIDENT_FILTERS,
  IncidentFilters,
  type IncidentFilterState,
} from '../components/incidents/IncidentFilters'
import { LogUploadControl } from '../components/ingest/LogUploadControl'
import { AiOpinionPanel } from '../components/logs/AiOpinionPanel'
import { TelemetryProfilePanel } from '../components/logs/TelemetryProfilePanel'
import {
  Button,
  Card,
  DataTable,
  applySort,
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
import { activityAnchorMs, bucketCounts, periodDelta } from '../lib/aggregations'
import { SEVERITY_ACCENT, SEVERITY_RANK } from '../lib/severity'
import { filterIncidents, primaryTactic } from '../lib/filtering'
import { formatDateTime, incidentRef } from '../lib/format'
import { SEVERITY_HEX } from '../lib/tokens'
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
  const severityParam = searchParams.get('severity')
  const statusParam = searchParams.get('status')
  const [filters, setFilters] = useState<IncidentFilterState>(() => ({
    ...DEFAULT_INCIDENT_FILTERS,
    severity: (severityParam as Severity | null) ?? 'all',
    status: statusParam ?? 'all',
  }))
  const paramKey = `${severityParam ?? ''}|${statusParam ?? ''}`
  const [seenParamKey, setSeenParamKey] = useState(paramKey)
  if (paramKey !== seenParamKey) {
    setSeenParamKey(paramKey)
    setFilters((current) => ({
      ...current,
      severity: (severityParam as Severity | null) ?? 'all',
      status: statusParam ?? 'all',
    }))
  }
  const [sort, setSort] = useState<SortState | null>(null)
  const [page, setPage] = useState(0)
  const [pageSize, setPageSize] = useState(prefs.pageSize)
  // Coverage-honesty panels for an upload made from this page -- same
  // pattern as LogsPage.tsx. Before this, IngestResponse was discarded
  // here entirely (onSuccess={refresh}), so ai_opinion_id, uncovered_events
  // and the coverage breakdown never reached the screen for an upload made
  // from Incidents, only the toast.
  const [aiOpinionId, setAiOpinionId] = useState<number | null>(null)
  const [lastIngest, setLastIngest] = useState<IngestResponse | null>(null)

  function handleUploadSuccess(res: IngestResponse) {
    setAiOpinionId(res.ai_opinion_id)
    setLastIngest(res)
    refresh()
  }

  const filtered = useMemo(() => filterIncidents(incidents, filters, byId), [incidents, filters, byId])
  const times = incidents.map((incident) => incident.created_at)
  // Same historical-dataset anchor as the Dashboard (see DashboardPage.tsx)
  // instead of Date.now(): incident.created_at is the real historical
  // EVTX event time, not upload time.
  const activityNow = activityAnchorMs(times)

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
      sortValue: (incident) => SEVERITY_RANK[incident.severity] ?? 0,
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
        <span className="font-mono text-meta text-accent-magenta">{incident.mitre_technique_ids[0] ?? '--'}</span>
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

  // Sort the WHOLE filtered list, then page it -- sorting only the visible
  // page made "sort by severity" show page 1's critical incidents first and
  // hide the rest on later pages.
  const visible = applySort(filtered, columns, sort).slice(page * pageSize, page * pageSize + pageSize)

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
        icon={<ShieldAlert className="h-5 w-5 text-accent-primary" />}
        breadcrumbs={[{ label: 'Overview', to: '/' }, { label: 'Incidents' }]}
        actions={<LogUploadControl onSuccess={handleUploadSuccess} />}
      />

      <TelemetryProfilePanel ingest={lastIngest} hasAiOpinion={aiOpinionId !== null} />
      <AiOpinionPanel
        opinionId={aiOpinionId}
        hasUncoveredEvents={(lastIngest?.uncovered_events ?? 0) > 0}
        hasDetections={(lastIngest?.rule_matches ?? 0) > 0}
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3 xl:grid-cols-5">
        <StatCard
          label="Total"
          value={meta.totalAll}
          icon={<ShieldAlert className="h-4 w-4" />}
          accent="primary"
          delta={periodDelta(times, 24, activityNow)}
          trend={bucketCounts(times, 12, 24, activityNow)}
        />
        {/* Accents come from SEVERITY_ACCENT rather than being chosen here,
            so these four can never drift from the severity ramp used by
            badges, heatmap cells and chart series. */}
        <StatCard
          label="Critical"
          value={meta.totalCritical}
          icon={<ShieldAlert className="h-4 w-4" />}
          accent={SEVERITY_ACCENT.critical}
          note="Highest severity band"
        />
        <StatCard
          label="High"
          value={meta.totalHigh}
          icon={<ShieldAlert className="h-4 w-4" />}
          accent={SEVERITY_ACCENT.high}
          note="Second severity band"
        />
        <StatCard
          label="Medium"
          value={meta.totalMedium}
          icon={<ShieldAlert className="h-4 w-4" />}
          accent={SEVERITY_ACCENT.medium}
          note="Third severity band"
        />
        <StatCard
          label="Low"
          value={meta.totalLow}
          icon={<ShieldAlert className="h-4 w-4" />}
          accent={SEVERITY_ACCENT.low}
          note={
            meta.totalInformational > 0
              ? `Lowest severity band -- plus ${meta.totalInformational} informational`
              : 'Lowest severity band'
          }
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
          rowAccent={(incident) => SEVERITY_HEX[incident.severity]}
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
