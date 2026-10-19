import { AlertTriangle, Database, EyeOff, FileText, List, ScrollText, TriangleAlert } from 'lucide-react'
import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import type { EventLogRow, IngestResponse } from '../api'
import { LogUploadControl } from '../components/ingest/LogUploadControl'
import { useIngest } from '../context/ingest/useIngest'
import { AiOpinionPanel } from '../components/logs/AiOpinionPanel'
import { EventDetailDrawer } from '../components/logs/EventDetailDrawer'
import { TelemetryProfilePanel } from '../components/logs/TelemetryProfilePanel'
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
import { activityAnchorMs, topBy } from '../lib/aggregations'
import { ACCENT, SEVERITY_HEX } from '../lib/tokens'
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
  const eventParam = searchParams.get('event')
  const [selectedId, setSelectedId] = useState<number | null>(eventParam ? Number(eventParam) : null)
  // React to ?event= changes while already on this page (the command
  // palette navigates here with a new id) -- not only on first mount.
  const [seenEventParam, setSeenEventParam] = useState(eventParam)
  if (eventParam !== seenEventParam) {
    setSeenEventParam(eventParam)
    setSelectedId(eventParam ? Number(eventParam) : null)
  }

  // The typed term updates the input immediately; only the debounced copy
  // reaches the API, so a search is one request rather than one per key.
  const debouncedSearch = useDebouncedValue(filters.search)
  const { events, rawEvents, total, page, setPage, loading, error, refresh } = useEvents(
    { ...filters, search: debouncedSearch },
    pageSize,
  )
  const { eventTotal, alertTotal, routineTotal, uncoveredTotal, refresh: refreshEventTotals } = useEventTotals()
  const verifiedCleanTotal = Math.max(eventTotal - alertTotal - routineTotal - uncoveredTotal, 0)
  // Start from the session's latest upload, so one that finished while
  // another page was open still shows its verdict here.
  const { result: latestUpload } = useIngest()
  const [aiOpinionId, setAiOpinionId] = useState<number | null>(latestUpload?.ai_opinion_id ?? null)
  const [lastIngest, setLastIngest] = useState<IngestResponse | null>(latestUpload)

  function handleUploadSuccess(res: IngestResponse) {
    setAiOpinionId(res.ai_opinion_id)
    setLastIngest(res)
    refresh()
    // Without this, the KPI cards below (Events ingested/Alerting events/
    // Verified clean/No rule coverage/Detection rate) stay frozen at
    // whatever they were when this page first mounted -- refresh() above
    // only re-fetches the event table (useEvents), a separate hook.
    refreshEventTotals()
  }

  const detectionRatePercent = eventTotal > 0 ? (alertTotal / eventTotal) * 100 : 0
  const counts = levelCounts(rawEvents)
  const span = timeSpan(rawEvents)
  const hosts = topBy(rawEvents, (event) => event.host, 5)
  // Real EVTX timestamps, not upload time -- anchor to the most recent
  // record on this page rather than Date.now(), same fix as the
  // Dashboard's activity graphs (see DashboardPage.tsx).
  const activityNow = activityAnchorMs(rawEvents.map((event) => event.timestamp))
  const activity = activityByHour(rawEvents, 12, activityNow).map((point) => ({ label: point.label, events: point.count }))

  const levelSlices = [
    { name: 'Critical', value: counts.critical, color: ACCENT.red },
    { name: 'Error', value: counts.error, color: SEVERITY_HEX.high },
    { name: 'Warning', value: counts.warn, color: ACCENT.amber },
    // Violet, not magenta: "Info" is the calm end of the level ramp and is
    // usually ~100% of a page, so a hot accent would dominate the donut.
    { name: 'Info', value: counts.info, color: ACCENT.primary },
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
      cell: (event) => <span className="whitespace-nowrap text-text-muted">{eventTypeLabel(event.event_id, event.channel)}</span>,
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
      key: 'parentProcess',
      header: 'Parent process',
      hideBelow: 'xl',
      cell: (event) => <span className="font-mono text-meta text-text-muted">{event.parent_process ?? '--'}</span>,
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
        icon={<ScrollText className="h-5 w-5 text-accent-magenta" />}
        breadcrumbs={[{ label: 'Overview', to: '/' }, { label: 'Logs' }]}
        actions={<LogUploadControl onSuccess={handleUploadSuccess} />}
      />

      <TelemetryProfilePanel ingest={lastIngest} hasAiOpinion={aiOpinionId !== null} />
      <AiOpinionPanel
        opinionId={aiOpinionId}
        hasUncoveredEvents={(lastIngest?.uncovered_events ?? 0) > 0}
        hasDetections={(lastIngest?.rule_matches ?? 0) > 0}
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-6">
        <StatCard
          label="Events ingested"
          value={eventTotal}
          icon={<Database className="h-4 w-4" />}
          accent="magenta"
          note="Every record in the store"
        />
        <StatCard
          label="Alerting events"
          value={alertTotal}
          icon={<AlertTriangle className="h-4 w-4" />}
          accent="amber"
          note={eventTotal > 0 ? `${((alertTotal / eventTotal) * 100).toFixed(2)}% of all events` : 'No events yet'}
        />
        {/* Split from a single "Clean events" tile on purpose: "0 alerts"
            only means "verified clean" for an event a loaded rule actually
            evaluated. An event whose channel/type no loaded rule covers at
            all is a different, honest thing -- collapsing the two made
            zero-coverage telemetry (e.g. a Security-only file before Phase 2
            rules exist for it) look identical to a genuinely clean scan. */}
        <StatCard
          label="Checked, no match"
          value={verifiedCleanTotal}
          icon={<FileText className="h-4 w-4" />}
          accent="primary"
          note="A rule or detector evaluated it"
        />
        <StatCard
          label="Everyday events"
          value={routineTotal}
          icon={<FileText className="h-4 w-4" />}
          accent="green"
          note="Routine activity that needs no rule"
        />
        <StatCard
          label="Unchecked"
          value={uncoveredTotal}
          icon={<EyeOff className="h-4 w-4" />}
          accent="amber"
          note="Security-relevant, nothing evaluates it"
        />
        {/* All six tiles are whole-dataset totals. Anything scoped to the
            visible page lives in the side panels below, which say
            "Current page" on their own headings -- mixing a page-scoped
            number into this row made "0 errors" sit beside "37 alerting
            events" and read like a contradiction. */}
        <StatCard
          label="Alerting event rate"
          value={detectionRatePercent}
          icon={<TriangleAlert className="h-4 w-4" />}
          accent="violet"
          note={`${alertTotal.toLocaleString()} of ${eventTotal.toLocaleString()} events flagged -- not a detection-recall metric`}
          format={(v) => `${v.toFixed(2)}%`}
        />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <div className="flex flex-col gap-4 xl:col-span-8">
          <FilterBar
            search={
              <SearchInput
                value={filters.search}
                onChange={(search) => setFilters({ ...filters, search })}
                placeholder="Search process, parent process, command line, user or host..."
              />
            }
            filters={
              <>
                {/* Severity, not the old info/warn/error vocabulary: the
                    rest of the app speaks in severities, and this is now a
                    real server-side filter, so the row count and pagination
                    below describe the filtered set. */}
                <Select
                  label="Severity"
                  value={filters.severity}
                  onChange={(severity) => setFilters({ ...filters, severity: severity as EventFilters['severity'] })}
                  options={[
                    { label: 'All events', value: 'all' },
                    { label: 'Critical', value: 'critical' },
                    { label: 'High', value: 'high' },
                    { label: 'Medium', value: 'medium' },
                    { label: 'Low', value: 'low' },
                    { label: 'Clean (no detection)', value: 'clean' },
                  ]}
                  className="w-44"
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
          <Card title="Level breakdown" subtitle="Current page" accent="magenta">
            {levelSlices.length > 0 ? (
              <Donut slices={levelSlices} height={168} totalLabel="On page" />
            ) : (
              <p className="text-meta text-text-muted">Nothing on this page to break down.</p>
            )}
          </Card>

          <Card title="Top hosts" subtitle="Current page" accent="primary">
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

          <Card title="Ingest summary" accent="primary">
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
