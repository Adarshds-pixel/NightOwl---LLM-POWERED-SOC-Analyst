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

// Soft translucent fills (badge backgrounds) -- Tailwind v4 uses the `/10`
// opacity modifier rather than the removed `bg-opacity-*` utilities, so this
// needs its own literal map, same JIT-safe reasoning as the maps above.
export const SEVERITY_BG_SOFT_CLASSES: Record<Severity, string> = {
  informational: 'bg-severity-informational/10',
  low: 'bg-severity-low/10',
  medium: 'bg-severity-medium/10',
  high: 'bg-severity-high/10',
  critical: 'bg-severity-critical/10',
}

// Re-exported from lib/tokens.ts, the single JS-side mirror of the CSS
// custom properties -- recharts and inline SVG can't read CSS variables, so
// chart series need real hex. Kept as a re-export (not a second copy) so
// the old "keep these two lists in sync by hand" hazard is gone.
export { SEVERITY_HEX } from './tokens'

export function severityLabel(severity: Severity): string {
  return severity.charAt(0).toUpperCase() + severity.slice(1)
}

/** Ring/dot classes used by badges, legends and status dots. */
export const SEVERITY_RING_CLASSES: Record<Severity, string> = {
  informational: 'ring-severity-informational/25',
  low: 'ring-severity-low/25',
  medium: 'ring-severity-medium/25',
  high: 'ring-severity-high/25',
  critical: 'ring-severity-critical/25',
}

export const SEVERITY_BORDER_SOFT_CLASSES: Record<Severity, string> = {
  informational: 'border-severity-informational/30',
  low: 'border-severity-low/30',
  medium: 'border-severity-medium/30',
  high: 'border-severity-high/30',
  critical: 'border-severity-critical/30',
}

/** Severity -> accent channel, so a severity-coloured card can reuse the
 *  shared accent glow/icon-chip styling without a second colour system.
 *
 *  Mirrors the SEVERITY_HEX ramp exactly: low is lavender (green would read
 *  as "healthy" and is reserved for genuine success states), medium amber
 *  and high orange are distinct rather than both amber. */
export const SEVERITY_ACCENT: Record<Severity, 'neutral' | 'violet' | 'amber' | 'orange' | 'red'> = {
  informational: 'neutral',
  low: 'violet',
  medium: 'amber',
  high: 'orange',
  critical: 'red',
}

/** Severities an analyst actually filters by (informational is never
 *  assigned to an incident by severity_service, only to raw events). */
export const FILTERABLE_SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low']
