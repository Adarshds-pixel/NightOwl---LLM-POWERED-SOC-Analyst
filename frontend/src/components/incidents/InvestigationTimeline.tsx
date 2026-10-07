import { Radar } from 'lucide-react'
import type { TimelineEntry } from '../../lib/timeline'
import { eventTypeLabel } from '../../lib/events'
import { formatDateTime } from '../../lib/format'
import { ACCENT } from '../../lib/tokens'
import { Badge, Card, EmptyState, Timeline, TimelineItem } from '../ui'

function entryTitle(entry: TimelineEntry) {
  if (entry.isAlert) {
    return (
      <span className="flex flex-wrap items-center gap-1.5">
        {entry.kind === 'ml' && (
          <Badge accent="neutral" className="shrink-0">
            ML anomaly · not a detection
          </Badge>
        )}
        <span className="font-medium text-text">{entry.ruleTitle ?? 'Unknown rule'}</span>
        {entry.techniqueId && (
          <Badge accent="violet" className="shrink-0">
            {entry.techniqueId}
          </Badge>
        )}
      </span>
    )
  }
  const label = eventTypeLabel(entry.eventId, entry.channel)
  return <span className="text-text-dim">{entry.process ? `${label}: ${entry.process}` : label}</span>
}

function entryDetail(entry: TimelineEntry) {
  const fragments: { key: string; value: string }[] = []
  if (entry.parentProcess) fragments.push({ key: 'parent', value: entry.parentProcess })
  if (entry.user) fragments.push({ key: 'user', value: entry.user })
  if (entry.commandLine) fragments.push({ key: 'cmd', value: entry.commandLine })
  if (fragments.length === 0) return undefined

  return (
    <span className="flex flex-wrap gap-x-3 gap-y-0.5">
      {fragments.map((fragment) => (
        <span key={fragment.key} className="truncate font-mono text-micro">
          {fragment.key}: <span className="text-text-dim">{fragment.value}</span>
        </span>
      ))}
    </span>
  )
}

/**
 * "Every incident gets a timeline" (final_plan.md Phase 7): the same alert
 * and related-event data the Evidence tab already shows, reshaped into one
 * chronological narrative instead of a flat table -- what happened, in the
 * order it happened, each step clickable into its raw event record.
 * Builds no new data of its own; `entries` come from
 * `buildIncidentTimeline()` over the same IncidentDetailResponse the rest
 * of this page already fetched.
 */
export function InvestigationTimeline({
  entries,
  onSelectEvent,
}: {
  entries: TimelineEntry[]
  onSelectEvent: (eventId: number) => void
}) {
  return (
    <Card
      title="Investigation timeline"
      subtitle="Each alert's event and up to five neighbouring events, in the order they happened"
      icon={<Radar className="h-4 w-4" />}
      accent="primary"
    >
      {entries.length === 0 ? (
        <EmptyState message="No timeline data" hint="This incident has no alerts to build a timeline from." />
      ) : (
        <Timeline>
          {entries.map((entry) => (
            <TimelineItem
              key={entry.id}
              title={entryTitle(entry)}
              timestamp={formatDateTime(entry.timestamp)}
              detail={entryDetail(entry)}
              severity={entry.isAlert && entry.kind !== 'ml' ? (entry.severity ?? undefined) : undefined}
              accentColor={entry.isAlert && entry.kind !== 'ml' ? undefined : ACCENT.neutral}
              onClick={() => onSelectEvent(entry.id)}
            />
          ))}
        </Timeline>
      )}
    </Card>
  )
}
