import clsx from 'clsx'
import { Radio } from 'lucide-react'
import { useState } from 'react'
import { usePreferences } from '../../context/preferences/usePreferences'
import { useLiveLogStream } from '../../hooks/useLiveLogStream'
import { eventMessage, eventSource, levelFor } from '../../lib/events'
import { formatTimeOfDay } from '../../lib/format'
import { Card, EmptyState, ErrorState, LevelBadge, SkeletonRows, StatusDot, ViewAllLink } from '../ui'

/**
 * The live tail of GET /events. Polling, not streaming -- the backend has
 * no websocket or SSE endpoint, and the interval is whatever the user set
 * in Settings. Hovering pauses updates so a row cannot move under the
 * pointer mid-read; the header says which state it is in.
 */
export function LiveLogStreamPanel() {
  const { prefs } = usePreferences()
  const [paused, setPaused] = useState(false)
  const { events, loading, error, lastUpdated, refresh } = useLiveLogStream(14, prefs.logStreamIntervalMs, paused)
  const live = prefs.logStreamIntervalMs > 0 && !paused

  return (
    <Card
      title="Latest events"
      icon={<Radio className="h-3.5 w-3.5" />}
      accent="magenta"
      divided
      flush
      bodyClassName="flex flex-col justify-center"
      action={
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1.5 text-micro text-text-faint">
            <StatusDot tone={live ? 'good' : 'idle'} pulse={live} />
            {live ? 'Auto-refresh' : paused ? 'Paused' : 'Manual'}
            {lastUpdated && <span className="hidden sm:inline">- {formatTimeOfDay(new Date(lastUpdated).toISOString())}</span>}
          </span>
          <ViewAllLink to="/logs" label="All logs" />
        </div>
      }
    >
      <div
        onMouseEnter={() => setPaused(true)}
        onMouseLeave={() => setPaused(false)}
        className="max-h-[268px] overflow-y-auto"
      >
        {loading ? (
          <SkeletonRows rows={6} />
        ) : error ? (
          <ErrorState message={error} onRetry={refresh} />
        ) : events.length === 0 ? (
          <EmptyState message="No events ingested yet" hint="Upload an EVTX file or run Demo Mode to populate the stream." />
        ) : (
          <table className="w-full border-collapse text-body">
            <thead className="sticky top-0 z-10">
              <tr className="bg-surface-2/85 backdrop-blur-sm">
                {['Time', 'Level', 'Source', 'Message'].map((heading) => (
                  <th
                    key={heading}
                    scope="col"
                    className="border-b border-line px-3 py-2 text-left text-micro font-semibold tracking-[0.12em] text-text-muted uppercase"
                  >
                    {heading}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {events.map((event) => {
                const level = levelFor(event.severity, event.is_alert)
                return (
                  <tr
                    key={event.id}
                    className={clsx(
                      'border-b border-line-soft transition-colors last:border-b-0 hover:bg-line-soft',
                      level === 'critical' && 'bg-severity-critical/6',
                    )}
                  >
                    <td className="px-3 py-1.5 font-mono text-micro whitespace-nowrap text-text-muted tabular-nums">
                      {formatTimeOfDay(event.timestamp)}
                    </td>
                    <td className="px-3 py-1.5">
                      <LevelBadge level={level} />
                    </td>
                    <td className="px-3 py-1.5 text-meta whitespace-nowrap text-text-muted">{eventSource(event)}</td>
                    <td className="max-w-0 px-3 py-1.5 text-meta">
                      <span className="block truncate text-text-dim">{eventMessage(event)}</span>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>
    </Card>
  )
}
