import { useParams } from 'react-router-dom'
import type { IncidentStatus } from '../api'
import { AuditTrail } from '../components/incidents/AuditTrail'
import { EvidenceSourcePanel } from '../components/incidents/EvidenceSourcePanel'
import { ExplainButton } from '../components/incidents/ExplainButton'
import { StatusControl } from '../components/incidents/StatusControl'
import { EmptyState, ErrorState, LoadingState, Panel, SeverityBadge, StatusPill } from '../components/ui'
import { useIncidentsSnapshot } from '../context/incidents/useIncidentsSnapshot'
import { useExplain } from '../hooks/useExplain'
import { useIncidentDetail } from '../hooks/useIncidentDetail'
import { formatRelativeTime } from '../lib/format'

const STATUS_TONE: Record<IncidentStatus, 'good' | 'bad' | 'warn' | 'neutral'> = {
  open: 'bad',
  investigating: 'warn',
  resolved: 'good',
  closed: 'neutral',
}

function IncidentDetailPage() {
  const { id } = useParams<{ id: string }>()
  const incidentId = Number(id)
  const { incident, loading, error, refresh } = useIncidentDetail(incidentId)
  const { refresh: refreshList } = useIncidentsSnapshot()
  const explain = useExplain(incidentId)

  function handleStatusChanged() {
    refresh()
    refreshList()
  }

  if (loading) {
    return (
      <div className="p-6">
        <LoadingState label="Loading incident" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="p-6">
        <ErrorState message={error} onRetry={refresh} />
      </div>
    )
  }

  if (!incident) return null

  return (
    <div className="space-y-6 p-6">
      <div>
        <div className="flex flex-wrap items-center gap-3">
          <h1 className="text-2xl font-semibold tracking-tight text-text">{incident.title}</h1>
          <SeverityBadge severity={incident.severity} />
          <StatusPill tone={STATUS_TONE[incident.status]} label={incident.status.toUpperCase()} />
        </div>
        <p className="mt-1 text-sm text-text-muted">
          Incident #{incident.id} · {incident.host} · {formatRelativeTime(incident.created_at)}
        </p>
      </div>

      <Panel title="Status" accent="cyan">
        <StatusControl incidentId={incident.id} currentStatus={incident.status} onChanged={handleStatusChanged} />
      </Panel>

      {incident.techniques.length > 0 && (
        <Panel title="MITRE Techniques" accent="purple">
          <div className="flex flex-wrap gap-2">
            {incident.techniques.map((technique) => (
              <span key={technique.id} className="rounded border border-accent-purple/30 px-2 py-1 text-xs text-text">
                <span className="text-accent-purple">{technique.id}</span> {technique.name}
              </span>
            ))}
          </div>
        </Panel>
      )}

      <Panel title="Alerts" accent="amber">
        {incident.alerts.length === 0 ? (
          <EmptyState message="No alerts recorded" />
        ) : (
          <div className="overflow-x-auto rounded border border-border">
            <table className="w-full text-sm">
              <thead className="border-b border-border bg-surface/60 text-left text-[10px] tracking-widest text-text-muted uppercase">
                <tr>
                  <th className="px-3 py-2 font-medium">Rule</th>
                  <th className="px-3 py-2 font-medium">Severity</th>
                  <th className="px-3 py-2 font-medium">Host</th>
                  <th className="px-3 py-2 font-medium">Process</th>
                  <th className="px-3 py-2 font-medium">User</th>
                  <th className="px-3 py-2 font-medium">Matched</th>
                </tr>
              </thead>
              <tbody>
                {incident.alerts.map((alert) => (
                  <tr key={alert.id} className="border-b border-border last:border-0">
                    <td className="px-3 py-2 text-text">{alert.rule_id}</td>
                    <td className="px-3 py-2">
                      <SeverityBadge severity={alert.severity} />
                    </td>
                    <td className="px-3 py-2 text-text-muted">{alert.event.host}</td>
                    <td className="px-3 py-2 text-text-muted">{alert.event.process ?? '--'}</td>
                    <td className="px-3 py-2 text-text-muted">{alert.event.user ?? '--'}</td>
                    <td className="px-3 py-2 text-text-muted">{formatRelativeTime(alert.matched_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <AuditTrail incidentId={incident.id} />

      <Panel title="AI Analysis" accent="purple">
        <ExplainButton status={explain.status} stageIndex={explain.stageIndex} onRun={explain.run} />
        <EvidenceSourcePanel
          status={explain.status}
          result={explain.result}
          error={explain.error}
          selfCritiqueFlagged={explain.selfCritiqueFlagged}
        />
      </Panel>
    </div>
  )
}

export default IncidentDetailPage
