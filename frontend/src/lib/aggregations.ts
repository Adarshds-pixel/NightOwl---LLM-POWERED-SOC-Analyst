import type { IncidentStatus, IncidentSummary, MitreTechnique, Severity } from '../api'
import { maxSeverity, SEVERITY_ORDER, SEVERITY_RANK } from './severity'
import { isTactic, TACTIC_LABELS, type Tactic } from './tactics'

export function severityDistribution(incidents: IncidentSummary[]): Record<Severity, number> {
  const dist = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, 0])) as Record<Severity, number>
  for (const incident of incidents) dist[incident.severity]++
  return dist
}

const STATUS_ORDER: IncidentStatus[] = ['open', 'investigating', 'resolved', 'closed']

export function statusDistribution(incidents: IncidentSummary[]): Record<IncidentStatus, number> {
  const dist = Object.fromEntries(STATUS_ORDER.map((s) => [s, 0])) as Record<IncidentStatus, number>
  for (const incident of incidents) dist[incident.status]++
  return dist
}

// Distinct real technique IDs actually observed across incidents -- never
// the full 858-entry MITRE catalog. Powers the dashboard's "Techniques
// Observed" KPI.
export function distinctTechniqueCount(incidents: IncidentSummary[]): number {
  return new Set(incidents.flatMap((i) => i.mitre_technique_ids)).size
}

export type ThreatLevel = 'NOMINAL' | 'LOW' | 'MODERATE' | 'ELEVATED' | 'CRITICAL'

// Derived purely from real open/investigating incident severities -- never
// a fabricated single number. If nothing is actively open, the level is
// NOMINAL regardless of historical (resolved/closed) severity.
export function computeThreatLevel(incidents: IncidentSummary[]): { level: ThreatLevel; activeCount: number } {
  const active = incidents.filter((i) => i.status === 'open' || i.status === 'investigating')
  if (active.length === 0) return { level: 'NOMINAL', activeCount: 0 }

  const top = maxSeverity(active.map((i) => i.severity))
  const levelBySeverity: Record<Severity, ThreatLevel> = {
    informational: 'LOW',
    low: 'LOW',
    medium: 'MODERATE',
    high: 'ELEVATED',
    critical: 'CRITICAL',
  }
  return { level: levelBySeverity[top], activeCount: active.length }
}

export interface SeverityTrendPoint {
  bucketLabel: string
  bucketStart: number
  counts: Record<Severity, number>
}

// Adaptive bucketing: hourly if the observed data spans <= 48h, otherwise
// daily -- avoids a hardcoded "last 24h" label that would misrepresent a
// dataset that actually spans weeks.
export function bucketizeSeverityTrend(incidents: IncidentSummary[]): {
  points: SeverityTrendPoint[]
  granularity: 'hourly' | 'daily'
} {
  if (incidents.length === 0) return { points: [], granularity: 'hourly' }

  const timestamps = incidents.map((i) => new Date(i.created_at).getTime())
  const minTs = Math.min(...timestamps)
  const maxTs = Math.max(...timestamps)
  const spanMs = Math.max(maxTs - minTs, 1)
  const granularity: 'hourly' | 'daily' = spanMs <= 48 * 60 * 60 * 1000 ? 'hourly' : 'daily'
  const bucketMs = granularity === 'hourly' ? 60 * 60 * 1000 : 24 * 60 * 60 * 1000

  const bucketStart = Math.floor(minTs / bucketMs) * bucketMs
  const bucketEnd = Math.ceil(maxTs / bucketMs) * bucketMs
  const buckets = new Map<number, Record<Severity, number>>()
  for (let t = bucketStart; t <= bucketEnd; t += bucketMs) {
    buckets.set(t, Object.fromEntries(SEVERITY_ORDER.map((s) => [s, 0])) as Record<Severity, number>)
  }

  for (const incident of incidents) {
    const ts = new Date(incident.created_at).getTime()
    const key = Math.floor(ts / bucketMs) * bucketMs
    const bucket = buckets.get(key)
    if (bucket) bucket[incident.severity]++
  }

  const points: SeverityTrendPoint[] = [...buckets.entries()]
    .sort(([a], [b]) => a - b)
    .map(([start, counts]) => ({
      bucketStart: start,
      bucketLabel:
        granularity === 'hourly'
          ? new Date(start).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false })
          : new Date(start).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
      counts,
    }))

  return { points, granularity }
}

export interface AttackVectorSlice {
  tactic: Tactic | 'other'
  label: string
  count: number
  percent: number
}

// Attribution rule (simple, defensible, disclosed in the UI): each
// incident's "primary" attack vector is the first tactic of its first
// listed MITRE technique. An incident with no resolvable technique/tactic
// is excluded from the denominator entirely (not silently folded into
// "other" as if it had a known-but-uncommon vector).
export function attackVectorBreakdown(
  incidents: IncidentSummary[],
  techniqueById: Map<string, MitreTechnique>,
): AttackVectorSlice[] {
  const counts = new Map<Tactic, number>()
  let attributed = 0

  for (const incident of incidents) {
    const firstTechniqueId = incident.mitre_technique_ids[0]
    if (!firstTechniqueId) continue
    const technique = techniqueById.get(firstTechniqueId)
    const firstTactic = technique?.tactics.find(isTactic)
    if (!firstTactic) continue
    counts.set(firstTactic, (counts.get(firstTactic) ?? 0) + 1)
    attributed++
  }

  if (attributed === 0) return []

  const sorted = [...counts.entries()].sort(([, a], [, b]) => b - a)
  const top = sorted.slice(0, 6)
  const rest = sorted.slice(6).reduce((sum, [, c]) => sum + c, 0)

  const slices: AttackVectorSlice[] = top.map(([tactic, count]) => ({
    tactic,
    label: TACTIC_LABELS[tactic],
    count,
    percent: (count / attributed) * 100,
  }))
  if (rest > 0) {
    slices.push({ tactic: 'other', label: 'Other', count: rest, percent: (rest / attributed) * 100 })
  }
  return slices
}

export interface HeatmapCellData {
  techniqueId: string
  techniqueName: string
  tactic: Tactic
  count: number
}

// Only techniques with >= 1 real hit are included -- never all 858
// catalog entries. A technique spanning multiple tactics appears once
// per tactic column it genuinely belongs to (matches the real MITRE
// ATT&CK matrix convention).
export function tacticTechniqueMatrix(
  incidents: IncidentSummary[],
  techniqueById: Map<string, MitreTechnique>,
): { cells: HeatmapCellData[]; tacticsPresent: Tactic[]; maxCount: number } {
  const hitCounts = new Map<string, number>()
  for (const incident of incidents) {
    for (const techniqueId of incident.mitre_technique_ids) {
      hitCounts.set(techniqueId, (hitCounts.get(techniqueId) ?? 0) + 1)
    }
  }

  const cells: HeatmapCellData[] = []
  const tacticsPresent = new Set<Tactic>()
  for (const [techniqueId, count] of hitCounts) {
    const technique = techniqueById.get(techniqueId)
    if (!technique) continue
    for (const tactic of technique.tactics) {
      if (!isTactic(tactic)) continue
      cells.push({ techniqueId, techniqueName: technique.name, tactic, count })
      tacticsPresent.add(tactic)
    }
  }

  const maxCount = cells.reduce((max, c) => Math.max(max, c.count), 0)
  return { cells, tacticsPresent: [...tacticsPresent], maxCount }
}

export interface TacticActivityCount {
  tactic: Tactic
  label: string
  count: number
}

// Total observed tactic activity -- unlike attackVectorBreakdown's
// single "primary vector" attribution (first technique's first tactic),
// this sums hits across *every* technique on every incident, so an
// incident touching 3 tactics contributes to all 3 here. Deliberately
// different framings: donut = primary-vector share, bars = total activity.
export function tacticActivityCounts(
  incidents: IncidentSummary[],
  techniqueById: Map<string, MitreTechnique>,
): TacticActivityCount[] {
  const { cells } = tacticTechniqueMatrix(incidents, techniqueById)
  const totals = new Map<Tactic, number>()
  for (const cell of cells) totals.set(cell.tactic, (totals.get(cell.tactic) ?? 0) + cell.count)

  return [...totals.entries()]
    .map(([tactic, count]) => ({ tactic, label: TACTIC_LABELS[tactic], count }))
    .sort((a, b) => b.count - a.count)
}

// "Most actionable" = highest-severity open incident, ties broken by most
// recent -- used by both QuickActionsPanel's "Run AI Analysis" and
// AiAssistantPanel's chat teaser, so the two dashboard widgets always agree
// on which incident they're pointing at. Only considers 'open' (not
// 'investigating') -- an incident already being worked shouldn't be the
// dashboard's top suggestion for where to start next.
export function selectMostActionableIncident(incidents: IncidentSummary[]): IncidentSummary | null {
  const open = incidents.filter((i) => i.status === 'open')
  if (open.length === 0) return null

  return open.reduce((best, current) => {
    const bySeverity = SEVERITY_RANK[current.severity] - SEVERITY_RANK[best.severity]
    if (bySeverity !== 0) return bySeverity > 0 ? current : best
    return new Date(current.created_at).getTime() > new Date(best.created_at).getTime() ? current : best
  })
}

export interface HostNode {
  host: string
  incidentCount: number
  severity: Severity
  techniqueIds: Set<string>
}

export interface HostEdge {
  a: string
  b: string
  sharedTechniqueCount: number
}

export function hostActivity(incidents: IncidentSummary[]): { nodes: HostNode[]; edges: HostEdge[] } {
  const byHost = new Map<string, { incidents: IncidentSummary[]; techniqueIds: Set<string> }>()
  for (const incident of incidents) {
    const entry = byHost.get(incident.host) ?? { incidents: [], techniqueIds: new Set<string>() }
    entry.incidents.push(incident)
    for (const id of incident.mitre_technique_ids) entry.techniqueIds.add(id)
    byHost.set(incident.host, entry)
  }

  const nodes: HostNode[] = [...byHost.entries()]
    .map(([host, entry]) => ({
      host,
      incidentCount: entry.incidents.length,
      severity: maxSeverity(entry.incidents.map((i) => i.severity)),
      techniqueIds: entry.techniqueIds,
    }))
    .sort((a, b) => b.incidentCount - a.incidentCount)

  const edges: HostEdge[] = []
  for (let i = 0; i < nodes.length; i++) {
    for (let j = i + 1; j < nodes.length; j++) {
      let shared = 0
      for (const id of nodes[i].techniqueIds) if (nodes[j].techniqueIds.has(id)) shared++
      if (shared > 0) edges.push({ a: nodes[i].host, b: nodes[j].host, sharedTechniqueCount: shared })
    }
  }

  return { nodes, edges }
}

/** The most recent timestamp actually present across one or more arrays of
 *  ISO timestamps, as epoch ms -- `null` when there is nothing to anchor
 *  to. NightOwl ingests historical EVTX archives (real-world fixtures span
 *  2019-2023; even the newest synthetic samples predate real wall-clock
 *  "now" by weeks), so any "last Nh" window measured from `Date.now()`
 *  is empty for virtually all real data. Call sites that render a
 *  recent-activity window should compute this once from whichever
 *  datasets feed that view and pass it as the shared `now` for every
 *  series in that view, instead of letting each aggregation default to
 *  `Date.now()` independently. */
export function latestTimestampMs(...timestampLists: string[][]): number | null {
  let latest: number | null = null
  for (const list of timestampLists) {
    for (const iso of list) {
      const time = new Date(iso).getTime()
      if (Number.isNaN(time)) continue
      if (latest === null || time > latest) latest = time
    }
  }
  return latest
}

/** `latestTimestampMs`, falling back to real wall-clock time when none of
 *  the given datasets have any timestamps at all (e.g. genuinely empty
 *  data, before anything has been ingested). Page components should call
 *  this rather than writing `?? Date.now()` inline -- `Date.now()` is an
 *  impure call, and keeping it in this plain module (not a component's
 *  render body) is what this project's lint config expects. */
export function activityAnchorMs(...timestampLists: string[][]): number {
  return latestTimestampMs(...timestampLists) ?? Date.now()
}

// --- Period-over-period deltas ------------------------------------------
// Every "+12% from yesterday" figure in the UI comes from here. It is a
// real comparison of two equal windows of ingested data, and it returns
// null rather than a number whenever the older window contains nothing to
// compare against -- the KPI card then says so instead of showing a
// fabricated percentage.

export interface PeriodDelta {
  percent: number
  label: string
  current: number
  previous: number
}

export function periodDelta(
  timestamps: string[],
  windowHours = 24,
  now = Date.now(),
): PeriodDelta | null {
  const windowMs = windowHours * 3600_000
  const currentStart = now - windowMs
  const previousStart = now - windowMs * 2

  let current = 0
  let previous = 0
  for (const iso of timestamps) {
    const time = new Date(iso).getTime()
    if (time >= currentStart) current++
    else if (time >= previousStart) previous++
  }

  // No prior window to compare with: a brand-new dataset is not a "100%
  // increase", it is simply an unknown trend.
  if (previous === 0) return null

  return {
    percent: ((current - previous) / previous) * 100,
    label: `vs previous ${windowHours}h`,
    current,
    previous,
  }
}

/** Counts per equal-width bucket over the last `hours`, oldest first --
 *  the shape KPI sparklines want. */
export function bucketCounts(timestamps: string[], buckets = 12, hours = 24, now = Date.now()): number[] {
  const spanMs = hours * 3600_000
  const bucketMs = spanMs / buckets
  const start = now - spanMs
  const counts = new Array<number>(buckets).fill(0)

  for (const iso of timestamps) {
    const time = new Date(iso).getTime()
    if (time < start || time > now) continue
    const index = Math.min(buckets - 1, Math.floor((time - start) / bucketMs))
    counts[index]++
  }
  return counts
}

/** Distinct hosts across a set of records -- the honest version of the
 *  mockups "assets monitored" tile: we know exactly which hosts have sent
 *  telemetry, so that is what the card reports. */
export function distinctHosts(records: { host: string }[]): string[] {
  return [...new Set(records.map((record) => record.host))].sort()
}

/** Generic "top N by count" over any key extractor, with the remainder
 *  folded into an explicit Other bucket when requested. */
export function topBy<T>(
  records: T[],
  key: (record: T) => string | null | undefined,
  limit = 5,
): { label: string; count: number }[] {
  const counts = new Map<string, number>()
  for (const record of records) {
    const value = key(record)
    if (!value) continue
    counts.set(value, (counts.get(value) ?? 0) + 1)
  }
  return [...counts.entries()]
    .sort(([, a], [, b]) => b - a)
    .slice(0, limit)
    .map(([label, count]) => ({ label, count }))
}
