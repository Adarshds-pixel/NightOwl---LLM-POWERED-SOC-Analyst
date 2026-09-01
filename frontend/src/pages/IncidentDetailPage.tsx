import { ArrowLeft, Bot, Crosshair, FileSearch, History, Server, ShieldAlert } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useLocation, useNavigate, useParams } from 'react-router-dom'
import { ChatPanel } from '../components/chat/ChatPanel'
import { AuditTrail } from '../components/incidents/AuditTrail'
import { EvidenceSourcePanel } from '../components/incidents/EvidenceSourcePanel'
import { ExplainButton } from '../components/incidents/ExplainButton'
import { StatusControl } from '../components/incidents/StatusControl'
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

type TabValue = 'overview' | 'evidence' | 'analysis' | 'chat' | 'audit'

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
  }

  if (loading) return <LoadingState label="Loading incident" className="py-24" />
  if (error) return <ErrorState className="py-24" message={error} onRetry={refresh} />
  if (!incident) return <ErrorState className="py-24" message="Incident not found" />

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
        icon={<ShieldAlert className="h-5 w-5 text-accent-blue" />}
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
          { value: 'evidence', label: 'Evidence', icon: <FileSearch className="h-3.5 w-3.5" />, count: incident.alerts.length },
          { value: 'analysis', label: 'AI analysis', icon: <Bot className="h-3.5 w-3.5" /> },
          { value: 'chat', label: 'Chat', icon: <Bot className="h-3.5 w-3.5" /> },
          { value: 'audit', label: 'Audit', icon: <History className="h-3.5 w-3.5" /> },
        ]}
      />

      {tab === 'overview' && (
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
          <Card title="MITRE techniques" icon={<Crosshair className="h-3.5 w-3.5" />} accent="cyan" className="xl:col-span-2">
            {incident.techniques.length === 0 ? (
              <p className="text-meta text-text-muted">No techniques resolved for this incident.</p>
            ) : (
              <ul className="flex flex-col gap-2">
                {incident.techniques.map((technique) => (
                  <li key={technique.id} className="rounded-control border border-line bg-surface-2/40 px-3 py-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-meta text-accent-cyan">{technique.id}</span>
                      <span className="text-body text-text-dim">{technique.name}</span>
                    </div>
                    <div className="mt-1 flex flex-wrap gap-1.5">
                      {technique.tactics.map((tactic) => (
                        <Badge key={tactic} accent="violet">
                          {tactic.replace(/-/g, ' ')}
                        </Badge>
                      ))}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </Card>

          <Card title="Affected asset" icon={<Server className="h-3.5 w-3.5" />} accent="green">
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

      {tab === 'evidence' && (
        <Card flush divided title={`${incident.alerts.length} alerts in this incident`}>
          <DataTable
            columns={alertColumns}
            rows={incident.alerts}
            rowKey={(alert) => alert.id}
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

      {tab === 'audit' && <AuditTrail incidentId={incident.id} />}
    </div>
  )
}

export default IncidentDetailPage
