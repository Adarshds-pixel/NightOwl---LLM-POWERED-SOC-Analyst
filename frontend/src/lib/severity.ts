import type { Severity } from '../api'

// Mirrors backend/app/services/severity_service.py's _RANK_LABELS verbatim.
export const SEVERITY_ORDER: Severity[] = [
  'informational',
  'low',
  'medium',
  'high',
  'critical',
]

export const SEVERITY_RANK: Record<Severity, number> = {
  informational: 1,
  low: 2,
  medium: 3,
  high: 4,
  critical: 5,
}

export function maxSeverity(severities: Severity[]): Severity {
  return severities.reduce((max, s) => (SEVERITY_RANK[s] > SEVERITY_RANK[max] ? s : max), 'informational' as Severity)
}

// Full class strings, not template-literal interpolation -- Tailwind's JIT
// scanner only detects complete literal class names in source, not
// dynamically-built ones. Every consumer must index into these records,
// never build a `bg-severity-${x}` string at runtime.
export const SEVERITY_BG_CLASSES: Record<Severity, string> = {
  informational: 'bg-severity-informational',
  low: 'bg-severity-low',
  medium: 'bg-severity-medium',
  high: 'bg-severity-high',
  critical: 'bg-severity-critical',
}

export const SEVERITY_TEXT_CLASSES: Record<Severity, string> = {
  informational: 'text-severity-informational',
  low: 'text-severity-low',
  medium: 'text-severity-medium',
  high: 'text-severity-high',
  critical: 'text-severity-critical',
}

export const SEVERITY_BORDER_CLASSES: Record<Severity, string> = {
  informational: 'border-severity-informational',
  low: 'border-severity-low',
  medium: 'border-severity-medium',
  high: 'border-severity-high',
  critical: 'border-severity-critical',
}

// Hex values duplicated from src/index.css's @theme block (Tailwind slate/emerald/amber/orange/red
// tokens) -- recharts renders to SVG/canvas and cannot read CSS custom properties as prop values,
// so chart series colors need real hex here, kept in lockstep with the CSS tokens by hand.
export const SEVERITY_HEX: Record<Severity, string> = {
  informational: '#94a3b8', // slate-400
  low: '#10b981', // emerald-500
  medium: '#f59e0b', // amber-500
  high: '#f97316', // orange-500
  critical: '#dc2626', // red-600
}

export function severityLabel(severity: Severity): string {
  return severity.charAt(0).toUpperCase() + severity.slice(1)
}
