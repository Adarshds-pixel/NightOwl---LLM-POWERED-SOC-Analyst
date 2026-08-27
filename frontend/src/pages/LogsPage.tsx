import { AlertTriangle, Database, FileText, List, ScrollText, TriangleAlert } from 'lucide-react'
import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import type { EventLogRow } from '../api'
import { LogUploadControl } from '../components/ingest/LogUploadControl'
import { EventDetailDrawer } from '../components/logs/EventDetailDrawer'
import {
  Button,
  Card,
  DataTable,
  Donut,
  FilterBar,
  LevelBadge,
  MiniStat,
  Pagination,
  PageHeader,
  SearchInput,
  Select,
  StatCard,
  TrendChart,
  type Column,
  type SortState,
} from '../components/ui'
import { usePreferences } from '../context/preferences/usePreferences'
import { useDebouncedValue } from '../hooks/useDebouncedValue'
import { EMPTY_EVENT_FILTERS, useEvents, type EventFilters } from '../hooks/useEvents'
import { useEventTotals } from '../hooks/useEventTotals'
import { activityByHour, eventMessage, eventTypeLabel, levelCounts, levelFor, timeSpan } from '../lib/events'
import { formatDateTime } from '../lib/format'
import { topBy } from '../lib/aggregations'
import { ACCENT } from '../lib/tokens'
import { SYSMON_EVENT_TYPE_LABELS } from '../lib/constants'

/**
 * The log explorer: the complete ingested event timeline, signal and noise
 * together. Search, host and alert-only filters go to the API; level and
 * event-type narrowing happen on the fetched page (the API has no notion of
 * a log level -- it is derived from whether a rule matched and how severe
 * that rule is).
 */
function LogsPage() {
  const { prefs } = usePreferences()
  const [searchParams] = useSearchParams()
  const [filters, setFilters] = useState<EventFilters>(EMPTY_EVENT_FILTERS)
  const [pageSize, setPageSize] = useState(prefs.pageSize)
  const [sort, setSort] = useState<SortState | null>(null)
  const [selectedId, setSelectedId] = useState<number | null>(() => {
    const param = searchParams.get('event')
    return param ? Number(param) : null
  })

  // The typed term updates the input immediately; only the debounced copy
  // reaches the API, so a search is one request rather than one per key.
  const debouncedSearch = useDebouncedValue(filters.search)
  const { events, rawEvents, total, page, setPage, loading, error, refresh } = useEvents(
    { ...filters, search: debouncedSearch },
    pageSize,
  )
  const { eventTotal, alertTotal } = useEventTotals()

  const counts = levelCounts(rawEvents)
  const span = timeSpan(rawEvents)
  const hosts = topBy(rawEvents, (event) => event.host, 5)
  const activity = activityByHour(rawEvents, 12).map((point) => ({ label: point.label, events: point.count }))

  const levelSlices = [
    { name: 'Critical', value: counts.critical, color: ACCENT.red },
    { name: 'Error', value: counts.error, color: '#f97316' },
    { name: 'Warning', value: counts.warn, color: ACCENT.amber },
    { name: 'Info', value: counts.info, color: ACCENT.cyan },
  ].filter((slice) => slice.value > 0)

  const columns: Column<EventLogRow>[] = [
    {
      key: 'time',
      header: 'Time',
      sortValue: (event) => event.timestamp,
      cell: (event) => (
        <span className="font-mono text-meta whitespace-nowrap text-text-muted">{formatDateTime(event.timestamp)}</span>
      ),
    },
    {
      key: 'level',
      header: 'Level',
      cell: (event) => <LevelBadge level={levelFor(event.severity, event.is_alert)} />,
    },
    {
      key: 'source',
      header: 'Source',
      hideBelow: 'md',
      cell: (event) => <span className="whitespace-nowrap text-text-muted">{eventTypeLabel(event.event_id)}</span>,
    },
    {
      key: 'host',
      header: 'Host',
      sortValue: (event) => event.host,
      cell: (event) => <span className="font-mono text-meta text-text-muted">{event.host}</span>,
    },
    {
      key: 'user',
      header: 'User',
      hideBelow: 'lg',
      cell: (event) => <span className="font-mono text-meta text-text-muted">{event.user ?? '--'}</span>,
    },
    {
      key: 'message',
      header: 'Message',
      className: 'max-w-0',
      cell: (event) => <span className="block truncate text-text-dim">{eventMessage(event)}</span>,
    },
    {
      key: 'details',
      header: '',
      align: 'right',
      cell: (event) => (
        <Button variant="icon" size="sm" aria-label="Show raw record" onClick={() => setSelectedId(event.id)}>
          <List className="h-3.5 w-3.5" />
        </Button>
      ),
    },
  ]

  return (
    <div className="flex flex-col gap-4 p-5">
      <PageHeader
        title="Logs"
        icon={<ScrollText className="h-5 w-5 text-accent-cyan" />}
        breadcrumbs={[{ label: 'Overview', to: '/' }, { label: 'Logs' }]}
        actions={<LogUploadControl onSuccess={refresh} />}
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Events ingested"
          value={eventTotal}
          icon={<Database className="h-4 w-4" />}
          accent="cyan"
          note="Every record in the store"
        />
        <StatCard
          label="Alerting events"
          value={alertTotal}
          icon={<AlertTriangle className="h-4 w-4" />}
          accent="amber"
          note={eventTotal > 0 ? `${((alertTotal / eventTotal) * 100).toFixed(2)}% of all events` : 'No events yet'}
        />
        <StatCard
          label="Errors on page"
          value={counts.error + counts.critical}
          icon={<TriangleAlert className="h-4 w-4" />}
          accent="red"
          note="High and critical rule matches"
        />
        <StatCard
          label="Warnings on page"
          value={counts.warn}
          icon={<FileText className="h-4 w-4" />}
          accent="violet"
          note="Medium severity matches"
        />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <div className="flex flex-col gap-4 xl:col-span-8">
          <FilterBar
            search={
              <SearchInput
                value={filters.search}
                onChange={(search) => setFilters({ ...filters, search })}
                placeholder="Search process, command line, user or host..."
              />
            }
            filters={
              <>
                <Select
                  label="Level"
                  value={filters.level}
                  onChange={(level) => setFilters({ ...filters, level: level as EventFilters['level'] })}
                  options={[
                    { label: 'All levels', value: 'all' },
                    { label: 'Critical', value: 'critical' },
                    { label: 'Error', value: 'error' },
                    { label: 'Warning', value: 'warn' },
                    { label: 'Info', value: 'info' },
                  ]}
                  className="w-36"
                />
                <Select
                  label="Event type"
                  value={String(filters.eventId)}
                  onChange={(value) =>
                    setFilters({ ...filters, eventId: value === 'all' ? 'all' : Number(value) })
                  }
                  options={[
                    { label: 'All types', value: 'all' },
                    ...Object.entries(SYSMON_EVENT_TYPE_LABELS).map(([id, label]) => ({ label, value: id })),
                  ]}
                  className="w-44"
                />
                <Select
                  label="Detections"
                  value={filters.alertOnly === null ? 'all' : filters.alertOnly ? 'alerts' : 'normal'}
                  onChange={(value) =>
                    setFilters({ ...filters, alertOnly: value === 'all' ? null : value === 'alerts' })
                  }
                  options={[
                    { label: 'All events', value: 'all' },
                    { label: 'Alerting only', value: 'alerts' },
                    { label: 'Non-alerting only', value: 'normal' },
                  ]}
                  className="w-44"
                />
              </>
            }
          />

          <Card flush divided title={`${total.toLocaleString()} events`}>
            <DataTable
              columns={columns}
              rows={events}
              rowKey={(event) => event.id}
              onRowClick={(event) => setSelectedId(event.id)}
              isRowActive={(event) => event.id === selectedId}
              sort={sort}
              onSortChange={setSort}
              loading={loading}
              error={error}
              onRetry={refresh}
              emptyMessage="No events match these filters"
              emptyHint="Clear a filter, or upload an EVTX export to ingest telemetry."
            />
            <Pagination
              page={page}
              pageSize={pageSize}
              total={total}
              onPageChange={setPage}
              onPageSizeChange={setPageSize}
              itemLabel="events"
            />
          </Card>
        </div>

        <div className="flex flex-col gap-4 xl:col-span-4">
          <Card title="Level breakdown" subtitle="Current page" accent="cyan">
            {levelSlices.length > 0 ? (
              <Donut slices={levelSlices} height={168} totalLabel="On page" />
            ) : (
              <p className="text-meta text-text-muted">Nothing on this page to break down.</p>
            )}
          </Card>

          <Card title="Top hosts" subtitle="Current page" accent="blue">
            <ul className="flex flex-col gap-2">
              {hosts.map((host) => (
                <li key={host.label} className="flex items-center justify-between gap-3 text-meta">
                  <span className="truncate font-mono text-text-dim">{host.label}</span>
                  <span className="font-mono text-text tabular-nums">{host.count}</span>
                </li>
              ))}
              {hosts.length === 0 && <li className="text-meta text-text-muted">No hosts on this page.</li>}
            </ul>
          </Card>

          <Card title="Activity" subtitle="Last 12 hours on this page" accent="violet">
            <TrendChart data={activity} series={[{ key: 'events', label: 'Events', color: ACCENT.violet }]} height={140} area />
          </Card>

          <Card title="Ingest summary" accent="green">
            <div className="grid grid-cols-2 gap-2">
              <MiniStat label="Events stored" value={eventTotal.toLocaleString()} />
              <MiniStat label="Alerting" value={alertTotal.toLocaleString()} />
              <MiniStat label="Hosts on page" value={new Set(rawEvents.map((event) => event.host)).size} />
              <MiniStat
                label="Page covers"
                value={span ? formatDateTime(span.from).split(',')[0] : '--'}
                note={span ? `to ${formatDateTime(span.to).split(',')[0]}` : undefined}
              />
            </div>
            <p className="mt-2 text-micro text-text-faint">
              NightOwl stores events in Postgres with no retention policy, so there is no expiry window to report.
            </p>
          </Card>
        </div>
      </div>

      <EventDetailDrawer eventId={selectedId} onClose={() => setSelectedId(null)} />
    </div>
  )
}

export default LogsPage
