import type { IncidentStatus, IncidentSummary, MitreTechnique, Severity } from '../api'
import { maxSeverity, SEVERITY_ORDER } from './severity'
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
