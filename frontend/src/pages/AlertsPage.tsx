import { Bell, ExternalLink, Eye, Siren } from 'lucide-react'
import { useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import type { AlertRow, Severity } from '../api'
import {
  Badge,
  Button,
  Card,
  DataTable,
  Donut,
  Drawer,
  FilterBar,
  KeyValue,
  Pagination,
  PageHeader,
  SearchInput,
  SegmentedControl,
  Select,
  SeverityBadge,
  StatCard,
  TrendChart,
  type Column,
  type SortState,
} from '../components/ui'
import { MlAnomalyEvidence } from '../components/incidents/MlAnomalyEvidence'
import { usePreferences } from '../context/preferences/usePreferences'
import { useDebouncedValue } from '../hooks/useDebouncedValue'
import { useAlerts } from '../hooks/useAlerts'
import { useRules } from '../hooks/useRules'
import { activityByHour, eventTypeLabel, levelFor } from '../lib/events'
import { formatDateTime, incidentRef } from '../lib/format'
import { SEVERITY_HEX, SEVERITY_RANK, severityLabel, FILTERABLE_SEVERITIES } from '../lib/severity'
import { activityAnchorMs, topBy } from '../lib/aggregations'
import { ACCENT } from '../lib/tokens'

/**
 * Alerts: every rule / sequence detection, one row per Alert record -- GET
 * /alerts?kind=detection (backend/app/api/routes_alerts.py). ML anomaly
 * records live behind their own tab: they are supporting evidence, not
 * detections, and never count toward an alert total.
 */
function AlertsPage() {
  const [searchParams] = useSearchParams()
  const [view, setView] = useState<'detection' | 'ml'>(searchParams.get('view') === 'ml' ? 'ml' : 'detection')
  const navigate = useNavigate()
  const { prefs } = usePreferences()
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState('all')
  const [selected, setSelected] = useState<AlertRow | null>(null)
  const [sort, setSort] = useState<SortState | null>(null)
  const [pageSize, setPageSize] = useState(prefs.pageSize)

  // Only the settled search term reaches the API -- see useDebouncedValue.
  const debouncedSearch = useDebouncedValue(search)
  // Severity goes to the server, so `total` (and the "N alerts" heading and
  // pagination below it) describe the filtered set rather than the whole
  // feed -- previously this narrowed one already-fetched page client-side,
  // which made a filtered view disagree with its own row count.
  const {
    alerts: events,
    total,
    page,
    setPage,
    loading,
    error,
    refresh,
  } = useAlerts({
    q: debouncedSearch || undefined,
    severity: severity === 'all' || view === 'ml' ? undefined : (severity as Severity),
    kind: view,
    limit: pageSize,
  })

  // Whole-feed counts for the KPI tiles, independent of which page is open
  // (one lightweight limit=1 request each, read for `total` only).
  const detectionTotal = useAlerts({ limit: 1, kind: 'detection' }).total
  const criticalTotal = useAlerts({ limit: 1, severity: 'critical', kind: 'detection' }).total
  const highTotal = useAlerts({ limit: 1, severity: 'high', kind: 'detection' }).total
  const anomalyTotal = useAlerts({ limit: 1, kind: 'ml' }).total
  // Rule definitions are session-cached (see useRules).
  const { rules } = useRules()
  const detectors = rules.filter((rule) => rule.kind !== 'ml')
  const rulesFiredTotal = detectors.filter((rule) => rule.match_count > 0).length

  const visible = events
  const bySeverity = FILTERABLE_SEVERITIES.map((level) => ({
    name: severityLabel(level),
    value: events.filter((event) => event.severity === level).length,
    color: SEVERITY_HEX[level],
  })).filter((slice) => slice.value > 0)

  const topRules = topBy(events, (event) => event.rule_title, 7)
  // Real EVTX timestamps, not upload time -- anchor to the most recent
  // alert on this page rather than Date.now(), same fix as the
  // Dashboard's activity graphs (see DashboardPage.tsx).
  const activityNow = activityAnchorMs(events.map((event) => event.timestamp))
  const isMl = view === 'ml'
  const activity = activityByHour(events, 12, activityNow).map((point) => ({ label: point.label, alerts: point.count }))

  const columns: Column<AlertRow>[] = [
    {
      key: 'time',
      header: 'Time',
      sortValue: (alert) => alert.timestamp,
      cell: (alert) => (
        <span className="font-mono text-meta whitespace-nowrap text-text-muted">{formatDateTime(alert.timestamp)}</span>
      ),
    },
    {
      key: 'severity',
      header: 'Severity',
      // By rank, not alphabetically ("critical" < "high" < "informational"...).
      sortValue: (alert) => (alert.severity ? SEVERITY_RANK[alert.severity] : 0),
      cell: (alert) =>
        alert.severity ? <SeverityBadge severity={alert.severity} score={alert.severity_score} /> : <span>--</span>,
    },
    {
      key: 'rule',
      header: 'Rule',
      sortValue: (alert) => alert.rule_title ?? '',
      className: 'max-w-[260px]',
      cell: (alert) => (
        <span className="flex items-center gap-1.5">
          {alert.kind === 'sequence' && <Badge accent="violet">Sequence</Badge>}
          {alert.occurrence_count > 1 && <Badge accent="neutral">x{alert.occurrence_count}</Badge>}
          <span className="block truncate text-text">{alert.rule_title ?? 'Unknown rule'}</span>
        </span>
      ),
    },
    {
      key: 'technique',
      header: 'Technique',
      hideBelow: 'md',
      cell: (alert) => <span className="font-mono text-meta text-accent-magenta">{alert.technique_id ?? '--'}</span>,
    },
    {
      key: 'source',
      header: 'Source',
      hideBelow: 'lg',
      cell: (alert) => <span className="text-text-muted">{eventTypeLabel(alert.event_id, alert.channel)}</span>,
    },
    {
      key: 'host',
      header: 'Host',
      sortValue: (alert) => alert.host,
      cell: (alert) => <span className="font-mono text-meta text-text-muted">{alert.host}</span>,
    },
    {
      key: 'incident',
      header: 'Incident',
      hideBelow: 'md',
      cell: (alert) =>
        alert.incident_id ? (
          <Badge accent="primary">{incidentRef(alert.incident_id)}</Badge>
        ) : (
          <span className="text-text-faint">ungrouped</span>
        ),
    },
    {
      key: 'actions',
      header: '',
      align: 'right',
      cell: (alert) => (
        <Button variant="icon" size="sm" aria-label="Inspect alert" onClick={() => setSelected(alert)}>
          <Eye className="h-3.5 w-3.5" />
        </Button>
      ),
    },
  ]

  return (
    <div className="flex flex-col gap-4 p-5">
      <PageHeader
        title="Alerts"
        icon={<Bell className="h-5 w-5 text-accent-amber" />}
        breadcrumbs={[{ label: 'Overview', to: '/' }, { label: 'Alerts' }]}
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {/* The tile matches the open tab; the other three always describe
            detections, and say so in the ML view. */}
        {isMl ? (
          <StatCard
            label="ML anomaly records"
            value={anomalyTotal}
            icon={<Bell className="h-4 w-4" />}
            accent="amber"
            note={`Advisory, never counted as detections · ${detectionTotal} detection(s) on the other tab`}
          />
        ) : (
          <StatCard
            label="Detections"
            value={detectionTotal}
            icon={<Bell className="h-4 w-4" />}
            accent="amber"
            note={`Rule and sequence alerts${anomalyTotal ? ` · ${anomalyTotal} ML anomaly record(s) shown separately` : ''}`}
          />
        )}
        {/* Whole-feed totals, not page-scoped -- a KPI row that mixed the
            two made a filtered or later page look like the alert counts had
            changed. Page-scoped breakdowns live in the side panels, which
            label themselves "Current page". */}
        <StatCard
          label="Critical"
          value={criticalTotal}
          icon={<Siren className="h-4 w-4" />}
          accent="red"
          note={isMl ? 'Detections only -- not ML records' : 'Across all detections'}
        />
        <StatCard
          label="High"
          value={highTotal}
          icon={<Siren className="h-4 w-4" />}
          accent="amber"
          note={isMl ? 'Detections only -- not ML records' : 'Across all detections'}
        />
        <StatCard
          label="Rules fired"
          value={rulesFiredTotal}
          icon={<Bell className="h-4 w-4" />}
          accent="violet"
          note={`of ${detectors.length} rules and sequence detectors`}
        />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <div className="flex flex-col gap-4 xl:col-span-8">
          <FilterBar
            search={<SearchInput value={search} onChange={setSearch} placeholder="Search alerts by process, parent process, command line, user or host..." />}
            filters={
              <div className="flex flex-wrap items-center gap-2">
              <SegmentedControl
                value={view}
                onChange={(value) => {
                  setView(value)
                  setSelected(null)
                }}
                options={[
                  { label: 'Detections', value: 'detection' },
                  { label: 'ML anomalies (experimental)', value: 'ml' },
                ]}
              />
              {!isMl && (
              <Select
                label="Severity"
                value={severity}
                onChange={setSeverity}
                options={[
                  { label: 'All severities', value: 'all' },
                  ...FILTERABLE_SEVERITIES.map((level) => ({ label: severityLabel(level), value: level })),
                ]}
                className="w-40"
              />
              )}
              </div>
            }
          />

          <Card
            flush
            divided
            title={isMl ? `${total.toLocaleString()} ML anomaly records` : `${total.toLocaleString()} detections`}
            subtitle={isMl ? 'Supporting evidence only -- unusual windows of log activity, not detections' : undefined}
          >
            <DataTable
              columns={columns}
              rows={visible}
              rowKey={(alert) => alert.alert_id}
              onRowClick={(alert) => setSelected(alert)}
              isRowActive={(alert) => selected?.alert_id === alert.alert_id}
              rowAccent={(alert) => (alert.severity && alert.kind !== 'ml' ? SEVERITY_HEX[alert.severity] : null)}
              sort={sort}
              onSortChange={setSort}
              loading={loading}
              error={error}
              onRetry={refresh}
              emptyMessage={isMl ? 'No ML anomaly records' : 'No detections match this search'}
              emptyHint={
                isMl
                  ? 'The anomaly model scores 10-minute windows of 10+ events per log; small uploads are never scored.'
                  : 'Detections appear after an uploaded log trips a rule; this page refreshes when reopened.'
              }
            />
            <Pagination
              page={page}
              pageSize={pageSize}
              total={total}
              onPageChange={setPage}
              onPageSizeChange={setPageSize}
              itemLabel={isMl ? 'records' : 'detections'}
            />
          </Card>
        </div>

        <div className="flex flex-col gap-4 xl:col-span-4">
          <Card title={isMl ? 'Records by severity' : 'Detections by severity'} subtitle="Current page" accent="red">
            {bySeverity.length > 0 ? <Donut slices={bySeverity} height={170} /> : <p className="text-meta text-text-muted">No alerts to break down.</p>}
          </Card>

          <Card title={isMl ? 'Top anomaly sources' : 'Top alerting rules'} subtitle="Current page" accent="violet">
            <ul className="flex flex-col gap-2">
              {topRules.map((rule) => (
                <li key={rule.label} className="flex items-center justify-between gap-3 text-meta">
                  <span className="truncate text-text-dim">{rule.label}</span>
                  <span className="font-mono text-text tabular-nums">{rule.count}</span>
                </li>
              ))}
              {topRules.length === 0 && <li className="text-meta text-text-muted">No rules have fired yet.</li>}
            </ul>
          </Card>

          <Card title="Activity over time" subtitle="12 hours up to the latest record on this page" accent="amber">
            <TrendChart data={activity} series={[{ key: 'alerts', label: 'Alerts', color: ACCENT.amber }]} height={150} area />
          </Card>
        </div>
      </div>

      <Drawer
        open={selected !== null}
        onClose={() => setSelected(null)}
        title={selected?.rule_title ?? 'Alert detail'}
        subtitle={selected ? `${selected.host} - ${formatDateTime(selected.timestamp)}` : undefined}
      >
        {selected && (
          <div className="flex flex-col gap-4 p-5">
            <dl className="grid grid-cols-2 gap-3">
              <KeyValue
                label="Severity"
                value={selected.severity ? <SeverityBadge severity={selected.severity} score={selected.severity_score} /> : '--'}
              />
              <KeyValue
                label="Technique"
                value={selected.kind === 'ml' ? 'None -- an anomaly maps to no single technique' : (selected.technique_id ?? '--')}
                mono={selected.kind !== 'ml'}
              />
              <KeyValue
                label="Raised by"
                value={selected.kind === 'ml' ? 'ML anomaly layer' : selected.kind === 'sequence' ? 'Sequence correlation' : 'Detection rule'}
              />
              {selected.occurrence_count > 1 && (
                <KeyValue label="Occurrences" value={`${selected.occurrence_count} identical matches folded into this alert`} />
              )}
              <KeyValue label="Event type" value={eventTypeLabel(selected.event_id, selected.channel)} />
              <KeyValue label="Level" value={levelFor(selected.severity, selected.is_alert).toUpperCase()} mono />
              <KeyValue label="Host" value={selected.host} mono />
              <KeyValue label="User" value={selected.user ?? '--'} mono />
              <KeyValue label="Process" value={selected.process ?? '--'} mono />
              <KeyValue label="Alert id" value={selected.alert_id} mono />
              <KeyValue label="Event id" value={selected.id} mono />
            </dl>

            {selected.kind === 'ml' && selected.details && <MlAnomalyEvidence details={selected.details} />}

            <div>
              <p className="text-micro font-medium tracking-[0.1em] text-text-faint uppercase">
                {selected.kind === 'ml' ? 'Representative event command line' : 'Command line'}
              </p>
              <pre className="mt-1 overflow-x-auto rounded-control border border-line bg-bg-deep/60 px-3 py-2 font-mono text-micro text-text-dim">
                {selected.command_line ?? 'Not recorded for this event type'}
              </pre>
            </div>

            <div className="flex flex-wrap gap-2">
              {selected.incident_id && (
                <Button
                  variant="primary"
                  onClick={() => navigate(`/incidents/${selected.incident_id}`)}
                  icon={<ExternalLink className="h-3.5 w-3.5" />}
                >
                  Open {incidentRef(selected.incident_id)}
                </Button>
              )}
              <Button variant="secondary" onClick={() => navigate(`/logs?event=${selected.id}`)}>
                View in logs
              </Button>
            </div>
          </div>
        )}
      </Drawer>
    </div>
  )
}

export default AlertsPage
