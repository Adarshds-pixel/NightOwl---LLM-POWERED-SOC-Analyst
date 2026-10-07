import type { EventLogRow, Severity } from '../api'
import {
  APPLICATION_EVENT_TYPE_LABELS,
  POWERSHELL_EVENT_TYPE_LABELS,
  SECURITY_EVENT_TYPE_LABELS,
  SYSMON_EVENT_TYPE_LABELS,
  SYSTEM_EVENT_TYPE_LABELS,
} from './constants'
import { bucketCounts } from './aggregations'
import type { LogLevel } from '../components/ui/Badge'

/**
 * Event-shaped derivations used by the Logs, Alerts and Live Log Stream
 * surfaces. Kept beside aggregations.ts (which is incident-shaped) rather
 * than inside components, so the same numbers cannot be computed two
 * slightly different ways on two pages.
 */

/** Channel family of a raw Windows channel string (mirrors the backend's
 *  normalizer.canonical_channel: exact names / log-path prefixes). */
export function channelFamily(channel: string | null | undefined): string | null {
  const c = (channel ?? '').trim().toLowerCase()
  if (!c) return null
  if (c === 'sysmon' || c.startsWith('microsoft-windows-sysmon/')) return 'sysmon'
  if (c === 'security') return 'security'
  if (c === 'powershell' || c === 'windows powershell' || c.startsWith('microsoft-windows-powershell/')) return 'powershell'
  if (c === 'system') return 'system'
  if (c === 'application') return 'application'
  return null
}

const LABELS_BY_FAMILY: Record<string, Record<number, string>> = {
  sysmon: SYSMON_EVENT_TYPE_LABELS,
  security: SECURITY_EVENT_TYPE_LABELS,
  powershell: POWERSHELL_EVENT_TYPE_LABELS,
  system: SYSTEM_EVENT_TYPE_LABELS,
  application: APPLICATION_EVENT_TYPE_LABELS,
}

/** Human label for an event id IN ITS CHANNEL, e.g. (1, Sysmon) ->
 *  "Process Creation". Without a recognised channel the honest answer is
 *  just the number -- the same id means different things in different logs. */
export function eventTypeLabel(eventId: number, channel?: string | null): string {
  const family = channelFamily(channel)
  const label = family ? LABELS_BY_FAMILY[family]?.[eventId] : undefined
  return label ?? `Event ${eventId}`
}

/** The "source" column in the mockups. NightOwl ingests Windows event logs
 *  from hosts, so the honest source of a row is its host plus the Sysmon
 *  channel the record came from. */
export function eventSource(event: EventLogRow): string {
  return eventTypeLabel(event.event_id, event.channel)
}

/** One-line human summary of a raw event, used where the mockups show a
 *  MESSAGE column. Built from real fields only -- process, command line,
 *  user -- never a templated narrative. */
export function eventMessage(event: EventLogRow): string {
  if (event.is_alert && event.rule_title) {
    return `${event.rule_title}: ${event.process ?? 'unknown process'}`
  }
  if (event.command_line) return event.command_line
  if (event.process) return `${eventTypeLabel(event.event_id, event.channel)}: ${event.process}`
  return eventTypeLabel(event.event_id, event.channel)
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
