import { useState } from 'react'
import { ExternalLink } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { useEventDetail } from '../../hooks/useEventDetail'
import { eventTypeLabel } from '../../lib/events'
import { formatDateTime, incidentRef } from '../../lib/format'
import { Badge, Button, Drawer, ErrorState, KeyValue, LoadingState, SeverityBadge, Tabs } from '../ui'

/**
 * The expanded view of one log row. Fetches GET /events/{id} on open, which
 * is the only endpoint that returns raw_json -- the fields normalization
 * flattened away (parent image, hashes, the network 5-tuple) live there and
 * nowhere else.
 */
export function EventDetailDrawer({ eventId, onClose }: { eventId: number | null; onClose: () => void }) {
  const navigate = useNavigate()
  const { event, loading, error } = useEventDetail(eventId)
  const [tab, setTab] = useState<'fields' | 'raw' | 'normalized'>('fields')

  return (
    <Drawer
      open={eventId !== null}
      onClose={onClose}
      title={event ? eventTypeLabel(event.event_id) : 'Event detail'}
      subtitle={event ? `${event.host} - ${formatDateTime(event.timestamp)}` : undefined}
    >
      {loading && <LoadingState label="Loading raw record" />}
      {error && <ErrorState message={error} />}
      {event && !loading && (
        <div className="flex flex-col gap-4 p-5">
          <div className="flex flex-wrap items-center gap-2">
            {event.severity ? <SeverityBadge severity={event.severity} /> : <Badge accent="magenta">Informational</Badge>}
            {event.rule_title && <Badge accent="amber">{event.rule_title}</Badge>}
            {event.technique_id && <Badge accent="violet">{event.technique_id}</Badge>}
            {event.incident_id && (
              <Button
                size="sm"
                variant="ghost"
                onClick={() => navigate(`/incidents/${event.incident_id}`)}
                icon={<ExternalLink className="h-3 w-3" />}
              >
                {incidentRef(event.incident_id)}
              </Button>
            )}
          </div>

          <Tabs
            value={tab}
            onChange={setTab}
            items={[
              { value: 'fields', label: 'Fields' },
              { value: 'raw', label: 'Raw record' },
              { value: 'normalized', label: 'Normalized' },
            ]}
          />

          {tab === 'fields' && (
            <dl className="grid grid-cols-2 gap-3">
              <KeyValue label="Event id" value={event.event_id} mono />
              <KeyValue label="Record" value={event.id} mono />
              <KeyValue label="Host" value={event.host} mono />
              <KeyValue label="User" value={event.user ?? '--'} mono />
              <KeyValue label="Process" value={event.process ?? '--'} mono />
              <KeyValue label="Timestamp" value={formatDateTime(event.timestamp)} mono />
              <div className="col-span-2">
                <p className="text-micro font-medium tracking-[0.1em] text-text-faint uppercase">Command line</p>
                <pre className="mt-1 overflow-x-auto rounded-control border border-line bg-bg-deep/60 px-3 py-2 font-mono text-micro whitespace-pre-wrap text-text-dim">
                  {event.command_line ?? 'Not recorded for this event type'}
                </pre>
              </div>
            </dl>
          )}

          {tab === 'raw' && <JsonView value={event.raw} emptyLabel="No raw payload stored for this record" />}
          {tab === 'normalized' && (
            <JsonView value={event.normalized} emptyLabel="No normalized view stored for this record" />
          )}
        </div>
      )}
    </Drawer>
  )
}

/** Pretty-printed JSON, styled as a code surface rather than a table --
 *  raw Windows event data is deeply nested and irregular, so any attempt to
 *  tabulate it would hide fields. */
export function JsonView({ value, emptyLabel }: { value: Record<string, unknown> | null; emptyLabel: string }) {
  if (!value || Object.keys(value).length === 0) {
    return <p className="text-meta text-text-muted">{emptyLabel}</p>
  }

  return (
    <pre className="max-h-[52vh] overflow-auto rounded-control border border-line bg-bg-deep/70 px-3 py-2.5 font-mono text-micro leading-relaxed text-text-dim">
      {JSON.stringify(value, null, 2)}
    </pre>
  )
}
