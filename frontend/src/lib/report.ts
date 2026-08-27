import type { IncidentSummary, MitreTechnique, RuleInfo } from '../api'
import { severityDistribution, statusDistribution, tacticActivityCounts } from './aggregations'
import { incidentRef } from './format'

/**
 * Report generation, done entirely client-side over data the API already
 * returned. There is no reports table and no report endpoint, so a
 * "generated report" here is exactly what it appears to be: a snapshot of
 * the live figures at the moment the button was pressed, exportable as
 * JSON, CSV or print/PDF. Nothing is stored server-side, and the UI says so.
 */

export type ReportWindow = '24h' | '7d' | '30d' | 'all'

export const REPORT_WINDOWS: { label: string; value: ReportWindow }[] = [
  { label: 'Last 24 hours', value: '24h' },
  { label: 'Last 7 days', value: '7d' },
  { label: 'Last 30 days', value: '30d' },
  { label: 'All ingested data', value: 'all' },
]

const WINDOW_HOURS: Record<ReportWindow, number | null> = {
  '24h': 24,
  '7d': 24 * 7,
  '30d': 24 * 30,
  all: null,
}

export interface ReportSnapshot {
  id: string
  generatedAt: string
  window: ReportWindow
  windowLabel: string
  incidentCount: number
  severity: Record<string, number>
  status: Record<string, number>
  hosts: { host: string; incidents: number }[]
  techniques: { id: string; name: string; detections: number }[]
  tactics: { label: string; count: number }[]
  rules: { title: string; matches: number; technique: string | null }[]
  incidents: IncidentSummary[]
}

export function buildReport(
  incidents: IncidentSummary[],
  techniqueById: Map<string, MitreTechnique>,
  rules: RuleInfo[],
  window: ReportWindow,
): ReportSnapshot {
  const hours = WINDOW_HOURS[window]
  const cutoff = hours === null ? null : Date.now() - hours * 3600_000
  const scoped = cutoff === null ? incidents : incidents.filter((i) => new Date(i.created_at).getTime() >= cutoff)

  const hostCounts = new Map<string, number>()
  const techniqueCounts = new Map<string, number>()
  for (const incident of scoped) {
    hostCounts.set(incident.host, (hostCounts.get(incident.host) ?? 0) + 1)
    for (const id of incident.mitre_technique_ids) {
      techniqueCounts.set(id, (techniqueCounts.get(id) ?? 0) + 1)
    }
  }

  return {
    id: `RPT-${Date.now().toString(36).toUpperCase()}`,
    generatedAt: new Date().toISOString(),
    window,
    windowLabel: REPORT_WINDOWS.find((entry) => entry.value === window)?.label ?? window,
    incidentCount: scoped.length,
    severity: severityDistribution(scoped),
    status: statusDistribution(scoped),
    hosts: [...hostCounts.entries()]
      .sort(([, a], [, b]) => b - a)
      .map(([host, incidents]) => ({ host, incidents })),
    techniques: [...techniqueCounts.entries()]
      .sort(([, a], [, b]) => b - a)
      .slice(0, 10)
      .map(([id, detections]) => ({ id, name: techniqueById.get(id)?.name ?? 'Unknown technique', detections })),
    tactics: tacticActivityCounts(scoped, techniqueById).map((entry) => ({ label: entry.label, count: entry.count })),
    rules: [...rules]
      .filter((rule) => rule.match_count > 0)
      .sort((a, b) => b.match_count - a.match_count)
      .slice(0, 10)
      .map((rule) => ({ title: rule.title, matches: rule.match_count, technique: rule.technique_id })),
    incidents: scoped,
  }
}

export function reportToCsv(report: ReportSnapshot): string {
  const header = ['reference', 'title', 'severity', 'status', 'host', 'techniques', 'detected_at']
  const rows = report.incidents.map((incident) =>
    [
      incidentRef(incident.id),
      incident.title,
      incident.severity,
      incident.status,
      incident.host,
      incident.mitre_technique_ids.join(' '),
      incident.created_at,
    ]
      .map(csvCell)
      .join(','),
  )
  return [header.join(','), ...rows].join('\n')
}

function csvCell(value: string): string {
  const needsQuotes = /[",\n]/.test(value)
  const escaped = value.replace(/"/g, '""')
  return needsQuotes ? `"${escaped}"` : escaped
}

/** Triggers a browser download of generated text. Everything stays local --
 *  no upload, no server round trip. */
export function downloadText(filename: string, contents: string, type: string): void {
  const blob = new Blob([contents], { type })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}
