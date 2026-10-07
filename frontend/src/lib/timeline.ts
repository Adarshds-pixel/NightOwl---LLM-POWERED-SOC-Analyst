import type { AlertInfo, AlertKind, Severity } from '../api'

/**
 * One step in an incident's investigation timeline (pending.md item 5 /
 * final_plan.md Phase 7): either the event that triggered one of the
 * incident's alerts, or a neighboring event on the same host that never
 * triggered anything itself but was ingested near one in time
 * (`AlertInfo.related_events`, already computed server-side -- see
 * incident_service.get_related_events). Built once from data
 * IncidentDetailResponse already carries; no separate fetch.
 */
export interface TimelineEntry {
  id: number
  timestamp: string
  eventId: number
  channel: string | null
  process: string | null
  parentProcess: string | null
  commandLine: string | null
  user: string | null
  isAlert: boolean
  ruleTitle: string | null
  techniqueId: string | null
  severity: Severity | null
  severityScore: number | null
  /** What raised this alert -- 'ml' entries are anomaly evidence, not detections. */
  kind: AlertKind | null
}

/**
 * Flattens every alert's own event plus its related events into one
 * chronological list, deduped by event id. An event can appear as the
 * trigger for one alert and as a "related" neighbor of another alert in
 * the same incident (or of two different alerts) -- the alert-triggering
 * version always wins, since it carries the rule/technique/severity
 * context the plain related-event shape doesn't have.
 */
export function buildIncidentTimeline(alerts: AlertInfo[]): TimelineEntry[] {
  const byId = new Map<number, TimelineEntry>()

  for (const alert of alerts) {
    byId.set(alert.event.id, {
      id: alert.event.id,
      timestamp: alert.event.timestamp,
      eventId: alert.event.event_id,
      channel: alert.event.channel ?? null,
      process: alert.event.process,
      parentProcess: alert.event.parent_process,
      commandLine: alert.event.command_line,
      user: alert.event.user,
      isAlert: true,
      ruleTitle: alert.rule_title,
      techniqueId: alert.technique_id,
      severity: alert.severity,
      severityScore: alert.severity_score,
      kind: alert.kind ?? 'sigma',
    })
  }

  for (const alert of alerts) {
    for (const related of alert.related_events) {
      if (byId.has(related.id)) continue
      byId.set(related.id, {
        id: related.id,
        timestamp: related.timestamp,
        eventId: related.event_id,
        channel: related.channel ?? null,
        process: related.process,
        parentProcess: null,
        commandLine: related.command_line,
        user: related.user,
        isAlert: false,
        ruleTitle: null,
        techniqueId: null,
        severity: null,
        severityScore: null,
        kind: null,
      })
    }
  }

  // Compared as instants, not strings: offsets can differ between rows.
  return [...byId.values()].sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp) || a.id - b.id)
}
