import type { AlertInfo } from '../../api'
import { eventTypeLabel } from '../../lib/events'
import { formatDateTime } from '../../lib/format'
import { Badge, Drawer, KeyValue, ListRow, SeverityBadge } from '../ui'

/**
 * The evidence-first alert view (pending.md item 5): everything one alert
 * carries -- rule, technique, host, user, process, command line, parent
 * process, related events, timestamps -- in one place, instead of the
 * evidence table's row implying "go read raw_json" for anything beyond
 * its handful of columns. Every field here is a direct read of
 * IncidentDetailResponse; no new analysis happens in this component.
 */
export function AlertEvidenceDrawer({ alert, onClose }: { alert: AlertInfo | null; onClose: () => void }) {
  return (
    <Drawer
      open={alert !== null}
      onClose={onClose}
      title={alert?.rule_title ?? (alert ? eventTypeLabel(alert.event.event_id) : 'Evidence')}
      subtitle={alert ? `${alert.event.host} — ${formatDateTime(alert.matched_at)}` : undefined}
    >
      {alert && (
        <div className="flex flex-col gap-4 p-5">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={alert.severity} score={alert.severity_score} />
            {alert.technique_id && <Badge accent="violet">{alert.technique_id}</Badge>}
          </div>

          <dl className="grid grid-cols-2 gap-3">
            <KeyValue label="Host" value={alert.event.host} mono />
            <KeyValue label="User" value={alert.event.user ?? '--'} mono />
            <KeyValue label="Process" value={alert.event.process ?? '--'} mono />
            <KeyValue label="Parent process" value={alert.event.parent_process ?? '--'} mono />
            <KeyValue label="Event type" value={eventTypeLabel(alert.event.event_id)} />
            <KeyValue label="Matched" value={formatDateTime(alert.matched_at)} mono />
          </dl>

          <div>
            <p className="text-micro font-medium tracking-[0.1em] text-text-faint uppercase">Command line</p>
            <pre className="mt-1 overflow-x-auto rounded-control border border-line bg-bg-deep/60 px-3 py-2 font-mono text-micro whitespace-pre-wrap text-text-dim">
              {alert.event.command_line ?? 'Not recorded for this event type'}
            </pre>
          </div>

          <div>
            <p className="mb-2 text-micro font-medium tracking-[0.1em] text-text-faint uppercase">
              Related events on this host — within 5 minutes
            </p>
            {alert.related_events.length === 0 ? (
              <p className="text-meta text-text-muted">
                No other ingested activity on this host within 5 minutes of this alert.
              </p>
            ) : (
              <ul className="flex flex-col gap-0.5">
                {alert.related_events.map((event) => (
                  <ListRow
                    key={event.id}
                    title={eventTypeLabel(event.event_id)}
                    meta={event.process ?? event.command_line ?? 'No process recorded'}
                    trailing={
                      <span className="font-mono text-micro whitespace-nowrap text-text-faint">
                        {formatDateTime(event.timestamp)}
                      </span>
                    }
                  />
                ))}
              </ul>
            )}
          </div>
        </div>
      )}
    </Drawer>
  )
}
