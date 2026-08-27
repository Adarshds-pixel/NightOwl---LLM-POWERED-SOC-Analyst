import { Bell, ExternalLink, Eye, Siren } from 'lucide-react'
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import type { EventLogRow } from '../api'
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
  Select,
  SeverityBadge,
  StatCard,
  TrendChart,
  type Column,
  type SortState,
} from '../components/ui'
import { usePreferences } from '../context/preferences/usePreferences'
import { useDebouncedValue } from '../hooks/useDebouncedValue'
import { EMPTY_EVENT_FILTERS, useEvents } from '../hooks/useEvents'
import { activityByHour, eventTypeLabel, levelFor } from '../lib/events'
import { formatDateTime, incidentRef } from '../lib/format'
import { SEVERITY_HEX, severityLabel, FILTERABLE_SEVERITIES } from '../lib/severity'
import { topBy } from '../lib/aggregations'
import { ACCENT } from '../lib/tokens'

/**
 * Alerts: every event that matched a detection rule.
 *
 * There is no /alerts endpoint -- alerts are rows in the alerts table,
 * surfaced through GET /events?alert_only=true along with the rule that
 * matched, the severity the engine assigned and the incident the alert was
 * grouped into. The status column is that parent incident status, which is
 * the only status an alert genuinely has.
 */
function AlertsPage() {
  const navigate = useNavigate()
  const { prefs } = usePreferences()
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState('all')
  const [selected, setSelected] = useState<EventLogRow | null>(null)
  const [sort, setSort] = useState<SortState | null>(null)
  const [pageSize, setPageSize] = useState(prefs.pageSize)

  // Only the settled search term reaches the API -- see useDebouncedValue.
  const debouncedSearch = useDebouncedValue(search)
  const { events, total, page, setPage, loading, error, refresh } = useEvents(
    { ...EMPTY_EVENT_FILTERS, search: debouncedSearch, alertOnly: true },
    pageSize,
  )

  const visible = severity === 'all' ? events : events.filter((event) => event.severity === severity)
  const bySeverity = FILTERABLE_SEVERITIES.map((level) => ({
    name: severityLabel(level),
    value: events.filter((event) => event.severity === level).length,
    color: SEVERITY_HEX[level],
  })).filter((slice) => slice.value > 0)

  const topRules = topBy(events, (event) => event.rule_title, 7)
  const activity = activityByHour(events, 12).map((point) => ({ label: point.label, alerts: point.count }))

  const columns: Column<EventLogRow>[] = [
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
      sortValue: (alert) => alert.severity ?? '',
      cell: (alert) => (alert.severity ? <SeverityBadge severity={alert.severity} /> : <span>--</span>),
    },
    {
      key: 'rule',
      header: 'Rule',
      sortValue: (alert) => alert.rule_title ?? '',
      className: 'max-w-[260px]',
      cell: (alert) => <span className="block truncate text-text">{alert.rule_title ?? 'Unknown rule'}</span>,
    },
    {
      key: 'technique',
      header: 'Technique',
      hideBelow: 'md',
      cell: (alert) => <span className="font-mono text-meta text-accent-cyan">{alert.technique_id ?? '--'}</span>,
    },
    {
      key: 'source',
      header: 'Source',
      hideBelow: 'lg',
      cell: (alert) => <span className="text-text-muted">{eventTypeLabel(alert.event_id)}</span>,
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
          <Badge accent="blue">{incidentRef(alert.incident_id)}</Badge>
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
        <StatCard
          label="Alerts raised"
          value={total}
          icon={<Bell className="h-4 w-4" />}
          accent="amber"
          note="Every rule match ever recorded"
        />
        <StatCard
          label="Critical"
          value={events.filter((event) => event.severity === 'critical').length}
          icon={<Siren className="h-4 w-4" />}
          accent="red"
          note="On this page"
        />
        <StatCard
          label="High"
          value={events.filter((event) => event.severity === 'high').length}
          icon={<Siren className="h-4 w-4" />}
          accent="amber"
          note="On this page"
        />
        <StatCard
          label="Distinct rules"
          value={new Set(events.map((event) => event.rule_title)).size}
          icon={<Bell className="h-4 w-4" />}
          accent="violet"
          note="Rules firing on this page"
        />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <div className="flex flex-col gap-4 xl:col-span-8">
          <FilterBar
            search={<SearchInput value={search} onChange={setSearch} placeholder="Search alerts by process, command line, user or host..." />}
            filters={
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
            }
          />

          <Card flush divided title={`${total.toLocaleString()} alerts`}>
            <DataTable
              columns={columns}
              rows={visible}
              rowKey={(alert) => alert.id}
              onRowClick={(alert) => setSelected(alert)}
              isRowActive={(alert) => selected?.id === alert.id}
              sort={sort}
              onSortChange={setSort}
              loading={loading}
              error={error}
              onRetry={refresh}
              emptyMessage="No alerts match this search"
              emptyHint="Alerts appear as soon as an ingested event trips a detection rule."
            />
            <Pagination
              page={page}
              pageSize={pageSize}
              total={total}
              onPageChange={setPage}
              onPageSizeChange={setPageSize}
              itemLabel="alerts"
            />
          </Card>
        </div>

        <div className="flex flex-col gap-4 xl:col-span-4">
          <Card title="Alerts by severity" subtitle="Current page" accent="red">
            {bySeverity.length > 0 ? <Donut slices={bySeverity} height={170} /> : <p className="text-meta text-text-muted">No alerts to break down.</p>}
          </Card>

          <Card title="Top alerting rules" subtitle="Current page" accent="violet">
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

          <Card title="Alerts over time" subtitle="Last 12 hours" accent="amber">
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
              <KeyValue label="Severity" value={selected.severity ? <SeverityBadge severity={selected.severity} /> : '--'} />
              <KeyValue label="Technique" value={selected.technique_id ?? '--'} mono />
              <KeyValue label="Event type" value={eventTypeLabel(selected.event_id)} />
              <KeyValue label="Level" value={levelFor(selected.severity, selected.is_alert).toUpperCase()} mono />
              <KeyValue label="Host" value={selected.host} mono />
              <KeyValue label="User" value={selected.user ?? '--'} mono />
              <KeyValue label="Process" value={selected.process ?? '--'} mono />
              <KeyValue label="Event id" value={selected.id} mono />
            </dl>

            <div>
              <p className="text-micro font-medium tracking-[0.1em] text-text-faint uppercase">Command line</p>
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
