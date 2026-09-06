import { ArrowLeft, Bot, Clock, FileSearch, History, Server, ShieldAlert } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useLocation, useNavigate, useParams } from 'react-router-dom'
import { ChatPanel } from '../components/chat/ChatPanel'
import { AlertEvidenceDrawer } from '../components/incidents/AlertEvidenceDrawer'
import { AuditTrail } from '../components/incidents/AuditTrail'
import { EvidenceSourcePanel } from '../components/incidents/EvidenceSourcePanel'
import { ExplainButton } from '../components/incidents/ExplainButton'
import { InvestigationTimeline } from '../components/incidents/InvestigationTimeline'
import { MitreEvidenceLinks } from '../components/incidents/MitreEvidenceLinks'
import { StatusControl } from '../components/incidents/StatusControl'
import { EventDetailDrawer } from '../components/logs/EventDetailDrawer'
import {
  Badge,
  Button,
  Card,
  DataTable,
  ErrorState,
  KeyValue,
  LoadingState,
  PageHeader,
  SeverityBadge,
  Tabs,
  type Column,
} from '../components/ui'
import { useIncidentsSnapshot } from '../context/incidents/useIncidentsSnapshot'
import { useExplain } from '../hooks/useExplain'
import { useIncidentDetail } from '../hooks/useIncidentDetail'
import type { AlertInfo } from '../api'
import { formatDateTime, formatDuration, formatRelativeTime, incidentRef } from '../lib/format'
import { eventTypeLabel } from '../lib/events'
import { buildIncidentTimeline } from '../lib/timeline'

type TabValue = 'overview' | 'timeline' | 'evidence' | 'analysis' | 'chat' | 'audit'

/**
 * Incident investigation view. Everything an analyst needs about one
 * incident, tabbed rather than stacked so the page does not become a very
 * long scroll: what happened, the raw alerts behind it, the AI analysis and
 * its sources, the conversation, and the audit trail.
 */
function IncidentDetailPage() {
  const { id } = useParams<{ id: string }>()
  const incidentId = Number(id)
  const navigate = useNavigate()
  const location = useLocation()
  const { incident, loading, error, refresh } = useIncidentDetail(incidentId)
  const { refresh: refreshList } = useIncidentsSnapshot()
  const explain = useExplain(incidentId)
  const [tab, setTab] = useState<TabValue>('overview')
  const [selectedAlert, setSelectedAlert] = useState<AlertInfo | null>(null)
  const [selectedEventId, setSelectedEventId] = useState<number | null>(null)
  // Bumped on every status change so AuditTrail (which owns its own
  // useIncidentAudit instance, not lifted up here) knows to refetch even
  // when a status change happens while the Audit tab is already mounted --
  // otherwise the trail only ever refetches on tab remount and misses the
  // status_change event just recorded.
  const [auditRefreshTick, setAuditRefreshTick] = useState(0)

  // Picked up once from the dashboard assistant card, then stripped from
  // history so a refresh or back-nav cannot re-trigger the auto-send.
  const [prefillChatMessage] = useState(
    () => (location.state as { prefillChatMessage?: string } | null)?.prefillChatMessage,
  )

  useEffect(() => {
    if (prefillChatMessage) {
      setTab('chat')
      navigate(location.pathname, { replace: true })
    }
  }, [prefillChatMessage, navigate, location.pathname])

  function handleStatusChanged() {
    refresh()
    refreshList()
    setAuditRefreshTick((tick) => tick + 1)
  }

  if (loading) return <LoadingState label="Loading incident" className="py-24" />
  if (error) return <ErrorState className="py-24" message={error} onRetry={refresh} />
  if (!incident) return <ErrorState className="py-24" message="Incident not found" />

  const timelineEntries = buildIncidentTimeline(incident.alerts)

  const alertColumns: Column<AlertInfo>[] = [
    {
      key: 'matched',
      header: 'Matched',
      cell: (alert) => (
        <span className="font-mono text-meta whitespace-nowrap text-text-muted">{formatDateTime(alert.matched_at)}</span>
      ),
    },
    {
      key: 'severity',
      header: 'Severity',
      cell: (alert) => <SeverityBadge severity={alert.severity} score={alert.severity_score} />,
    },
    {
      key: 'event',
      header: 'Event',
      cell: (alert) => <span className="text-text-dim">{eventTypeLabel(alert.event.event_id)}</span>,
    },
    {
      key: 'rule',
      header: 'Rule / technique',
      hideBelow: 'sm',
      cell: (alert) => (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="truncate text-meta text-text-dim">{alert.rule_title ?? 'Unknown rule'}</span>
          {alert.technique_id && (
            <Badge accent="violet" className="shrink-0">
              {alert.technique_id}
            </Badge>
          )}
        </div>
      ),
    },
    {
      key: 'process',
      header: 'Process',
      hideBelow: 'md',
      cell: (alert) => <span className="font-mono text-meta text-text-muted">{alert.event.process ?? '--'}</span>,
    },
    {
      key: 'user',
      header: 'User',
      hideBelow: 'lg',
      cell: (alert) => <span className="font-mono text-meta text-text-muted">{alert.event.user ?? '--'}</span>,
    },
    {
      key: 'command',
      header: 'Command line',
      className: 'max-w-[380px]',
      cell: (alert) => (
        <span className="block truncate font-mono text-micro text-text-muted">{alert.event.command_line ?? '--'}</span>
      ),
    },
  ]

  return (
    <div className="flex flex-col gap-4 p-5">
      <PageHeader
        title={incident.title}
        icon={<ShieldAlert className="h-5 w-5 text-accent-primary" />}
        breadcrumbs={[
          { label: 'Overview', to: '/' },
          { label: 'Incidents', to: '/incidents' },
          { label: incidentRef(incident.id) },
        ]}
        actions={
          <>
            <Button variant="ghost" onClick={() => navigate('/incidents')} icon={<ArrowLeft className="h-3.5 w-3.5" />}>
              Back to list
            </Button>
            <Button
              variant="secondary"
              onClick={() => navigate(`/assistant?incident=${incident.id}`)}
              icon={<Bot className="h-3.5 w-3.5" />}
            >
              Open in assistant
            </Button>
          </>
        }
      />

      <Card>
        <div className="flex flex-wrap items-start justify-between gap-4">
          <dl className="grid flex-1 grid-cols-2 gap-x-6 gap-y-3 sm:grid-cols-4">
            <KeyValue label="Severity" value={<SeverityBadge severity={incident.severity} score={incident.severity_score} />} />
            <KeyValue label="Host" value={incident.host} mono />
            <KeyValue label="Detected" value={formatDateTime(incident.created_at)} mono />
            <KeyValue label="Open for" value={formatDuration(incident.created_at)} mono />
            <KeyValue label="Alerts" value={incident.alerts.length} mono />
            <KeyValue label="Techniques" value={incident.mitre_technique_ids.length} mono />
            <KeyValue label="Reference" value={incidentRef(incident.id)} mono />
            <KeyValue label="Detection source" value="Sigma rules on ingested EVTX" />
          </dl>
          <StatusControl incidentId={incident.id} currentStatus={incident.status} onChanged={handleStatusChanged} />
        </div>
      </Card>

      <Tabs
        value={tab}
        onChange={setTab}
        items={[
          { value: 'overview', label: 'Overview', icon: <ShieldAlert className="h-3.5 w-3.5" /> },
          { value: 'timeline', label: 'Timeline', icon: <Clock className="h-3.5 w-3.5" />, count: timelineEntries.length },
          { value: 'evidence', label: 'Evidence', icon: <FileSearch className="h-3.5 w-3.5" />, count: incident.alerts.length },
          { value: 'analysis', label: 'AI analysis', icon: <Bot className="h-3.5 w-3.5" /> },
          { value: 'chat', label: 'Chat', icon: <Bot className="h-3.5 w-3.5" /> },
          { value: 'audit', label: 'Audit', icon: <History className="h-3.5 w-3.5" /> },
        ]}
      />

      {tab === 'overview' && (
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
          <MitreEvidenceLinks
            techniques={incident.techniques}
            alerts={incident.alerts}
            onSelectAlert={(alert) => {
              setSelectedEventId(null)
              setSelectedAlert(alert)
            }}
            className="xl:col-span-2"
          />

          <Card title="Affected asset" icon={<Server className="h-3.5 w-3.5" />} accent="primary">
            <dl className="flex flex-col gap-3">
              <KeyValue label="Host" value={incident.host} mono />
              <KeyValue
                label="Users seen"
                value={[...new Set(incident.alerts.map((alert) => alert.event.user).filter(Boolean))].join(', ') || '--'}
                mono
              />
              <KeyValue
                label="First alert"
                value={incident.alerts.length > 0 ? formatRelativeTime(incident.alerts[0].matched_at) : '--'}
              />
              <KeyValue
                label="Processes"
                value={[...new Set(incident.alerts.map((alert) => alert.event.process).filter(Boolean))].length}
                mono
              />
            </dl>
            <p className="mt-3 text-micro text-text-faint">
              NightOwl knows this host only through the telemetry it ingested; there is no separate asset inventory.
            </p>
          </Card>
        </div>
      )}

      {tab === 'timeline' && (
        <InvestigationTimeline
          entries={timelineEntries}
          onSelectEvent={(eventId) => {
            // Only one drawer at a time -- without this, an evidence-row
            // drawer left open from a previous tab visit would still be
            // "open" (state never resets on tab change) and stack behind
            // the event drawer this click is opening.
            setSelectedAlert(null)
            setSelectedEventId(eventId)
          }}
        />
      )}

      {tab === 'evidence' && (
        <Card flush divided title={`${incident.alerts.length} alerts in this incident`} subtitle="Click a row for the full evidence package">
          <DataTable
            columns={alertColumns}
            rows={incident.alerts}
            rowKey={(alert) => alert.id}
            onRowClick={(alert) => {
              setSelectedEventId(null)
              setSelectedAlert(alert)
            }}
            isRowActive={(alert) => alert.id === selectedAlert?.id}
            emptyMessage="No alerts attached to this incident"
          />
        </Card>
      )}

      {tab === 'analysis' && (
        <Card title="AI analysis" icon={<Bot className="h-3.5 w-3.5" />} accent="violet">
          <ExplainButton status={explain.status} stageIndex={explain.stageIndex} onRun={explain.run} />
          <div className="mt-4">
            <EvidenceSourcePanel
              status={explain.status}
              result={explain.result}
              error={explain.error}
              selfCritiqueFlagged={explain.selfCritiqueFlagged}
            />
          </div>
        </Card>
      )}

      {tab === 'chat' && <ChatPanel incidentId={incident.id} initialMessage={prefillChatMessage} />}

      {tab === 'audit' && <AuditTrail incidentId={incident.id} refreshSignal={auditRefreshTick} />}

      <AlertEvidenceDrawer alert={selectedAlert} onClose={() => setSelectedAlert(null)} />
      <EventDetailDrawer eventId={selectedEventId} onClose={() => setSelectedEventId(null)} />
    </div>
  )
}

export default IncidentDetailPage
