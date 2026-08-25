import { useState } from 'react'
import { EmptyState, ErrorState, LoadingState, Pagination, SeverityBadge, StatusPill } from '../components/ui'
import { useEvents } from '../hooks/useEvents'
import { EVENT_PAGE_SIZE, SYSMON_EVENT_TYPE_LABELS } from '../lib/constants'
import { formatRelativeTime } from '../lib/format'

function LogsPage() {
  const [hostInput, setHostInput] = useState('')
  const [host, setHost] = useState('')
  const [alertOnly, setAlertOnly] = useState(false)
  const { events, total, page, setPage, loading, error, refresh } = useEvents({ host, alertOnly })

  function applyHostFilter() {
    setHost(hostInput.trim())
  }

  return (
    <div className="space-y-4 p-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-text">Logs</h1>
        <p className="mt-1 text-sm text-text-muted">
          The full raw event timeline -- everything NightOwl ingested, not just what became an alert. Real SOC
          telemetry is almost entirely ordinary activity with a small number of genuine detections buried in it.
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <input
          type="text"
          value={hostInput}
          onChange={(e) => setHostInput(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && applyHostFilter()}
          onBlur={applyHostFilter}
          placeholder="Filter by host..."
          className="rounded border border-border bg-surface/60 px-3 py-1.5 text-sm text-text placeholder:text-text-muted focus:border-accent-cyan focus:outline-none"
        />
        <label className="flex items-center gap-2 text-sm text-text-muted">
          <input
            type="checkbox"
            checked={alertOnly}
            onChange={(e) => setAlertOnly(e.target.checked)}
            className="h-4 w-4 rounded border-border"
          />
          Suspicious only
        </label>
      </div>

      {loading && <LoadingState label="Fetching events" />}
      {error && !loading && <ErrorState message={error} onRetry={refresh} />}
      {!loading && !error && events.length === 0 && (
        <EmptyState message="No events match these filters -- ingest logs to populate the timeline" />
      )}

      {!loading && !error && events.length > 0 && (
        <div className="space-y-3">
          <div className="overflow-x-auto rounded border border-border">
            <table className="w-full text-sm">
              <thead className="border-b border-border bg-surface/60 text-left text-[10px] tracking-widest text-text-muted uppercase">
                <tr>
                  <th className="px-4 py-2 font-medium">Time</th>
                  <th className="px-4 py-2 font-medium">Host</th>
                  <th className="px-4 py-2 font-medium">Event Type</th>
                  <th className="px-4 py-2 font-medium">Process / Detail</th>
                  <th className="px-4 py-2 font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {events.map((event) => (
                  <tr key={event.id} className="border-b border-border last:border-0 hover:bg-surface/40">
                    <td className="px-4 py-2 whitespace-nowrap text-text-muted" title={event.timestamp}>
                      {formatRelativeTime(event.timestamp)}
                    </td>
                    <td className="px-4 py-2 text-text">{event.host}</td>
                    <td className="px-4 py-2 text-text-muted">
                      {SYSMON_EVENT_TYPE_LABELS[event.event_id] ?? `Event ${event.event_id}`}
                    </td>
                    <td className="max-w-md truncate px-4 py-2 text-text-muted" title={event.command_line ?? event.process ?? ''}>
                      {event.is_alert && event.rule_title ? (
                        <span className="text-text">
                          {event.rule_title}
                          {event.technique_id && <span className="ml-1.5 text-text-muted">({event.technique_id})</span>}
                        </span>
                      ) : (
                        event.command_line ?? event.process ?? '--'
                      )}
                    </td>
                    <td className="px-4 py-2">
                      {event.is_alert && event.severity ? (
                        <SeverityBadge severity={event.severity} />
                      ) : (
                        <StatusPill tone="good" label="Normal" />
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pagination page={page} pageSize={EVENT_PAGE_SIZE} total={total} onPageChange={setPage} />
        </div>
      )}
    </div>
  )
}

export default LogsPage
