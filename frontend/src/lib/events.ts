import type { EventLogRow, Severity } from '../api'
import { SYSMON_EVENT_TYPE_LABELS } from './constants'
import { bucketCounts } from './aggregations'
import type { LogLevel } from '../components/ui/Badge'

/**
 * Event-shaped derivations used by the Logs, Alerts and Live Log Stream
 * surfaces. Kept beside aggregations.ts (which is incident-shaped) rather
 * than inside components, so the same numbers cannot be computed two
 * slightly different ways on two pages.
 */

/** Sysmon event id -> human label, e.g. 1 -> "Process Creation". */
export function eventTypeLabel(eventId: number): string {
  return SYSMON_EVENT_TYPE_LABELS[eventId] ?? `Event ${eventId}`
}

/** The "source" column in the mockups. NightOwl ingests Windows event logs
 *  from hosts, so the honest source of a row is its host plus the Sysmon
 *  channel the record came from. */
export function eventSource(event: EventLogRow): string {
  return eventTypeLabel(event.event_id)
}

/** One-line human summary of a raw event, used where the mockups show a
 *  MESSAGE column. Built from real fields only -- process, command line,
 *  user -- never a templated narrative. */
export function eventMessage(event: EventLogRow): string {
  if (event.is_alert && event.rule_title) {
    return `${event.rule_title}: ${event.process ?? 'unknown process'}`
  }
  if (event.command_line) return event.command_line
  if (event.process) return `${eventTypeLabel(event.event_id)}: ${event.process}`
  return eventTypeLabel(event.event_id)
}

export interface LevelCounts {
  info: number
  warn: number
  error: number
  critical: number
}

export function levelFor(severity: Severity | null, isAlert: boolean): LogLevel {
  if (!isAlert || severity === null) return 'info'
  if (severity === 'critical') return 'critical'
  if (severity === 'high') return 'error'
  if (severity === 'medium') return 'warn'
  return 'info'
}

export function levelCounts(events: EventLogRow[]): LevelCounts {
  const counts: LevelCounts = { info: 0, warn: 0, error: 0, critical: 0 }
  for (const event of events) counts[levelFor(event.severity, event.is_alert)]++
  return counts
}

/** Activity buckets for the log/alert trend charts, labelled by hour. */
export function activityByHour(
  events: { timestamp: string }[],
  hours = 12,
  now = Date.now(),
): { label: string; count: number }[] {
  const counts = bucketCounts(
    events.map((event) => event.timestamp),
    hours,
    hours,
    now,
  )
  return counts.map((count, index) => {
    const bucketTime = new Date(now - (hours - 1 - index) * 3600_000)
    return { label: `${String(bucketTime.getHours()).padStart(2, '0')}:00`, count }
  })
}

/** Time span covered by a set of events, as ISO bounds. Used by the Logs
 *  ingest summary instead of the mockups fabricated storage/retention
 *  tile -- we genuinely know the first and last timestamp we hold. */
export function timeSpan(events: { timestamp: string }[]): { from: string; to: string } | null {
  if (events.length === 0) return null
  let min = events[0].timestamp
  let max = events[0].timestamp
  for (const event of events) {
    if (event.timestamp < min) min = event.timestamp
    if (event.timestamp > max) max = event.timestamp
  }
  return { from: min, to: max }
}
