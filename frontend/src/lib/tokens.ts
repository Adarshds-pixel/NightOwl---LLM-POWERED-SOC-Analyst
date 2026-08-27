/**
 * JS mirror of the CSS custom properties in src/index.css.
 *
 * recharts props and inline SVG attributes are plain strings -- they can't
 * resolve `var(--color-severity-high)` -- so every chart and hand-drawn
 * visual reads its colours from here instead of hard-coding hexes at the
 * call site (which is how the old chartTheme/severity/HeatmapGrid trio
 * drifted apart). If a value changes in index.css, change it here too;
 * nothing else in the app should contain a raw hex.
 */

export const SURFACE = {
  bg: '#060a14',
  bgDeep: '#04070f',
  surface: '#0b1220',
  surface1: '#0d1526',
  surface2: '#111b30',
  surface3: '#16223c',
  elevated: '#131d33',
} as const

export const LINE = {
  soft: 'rgba(120, 160, 255, 0.07)',
  base: 'rgba(120, 160, 255, 0.10)',
  strong: 'rgba(125, 180, 255, 0.22)',
} as const

export const TEXT = {
  base: '#e8eefc',
  dim: '#9fb0d0',
  muted: '#6b7fa4',
  faint: '#55658a',
} as const

export const ACCENT = {
  blue: '#3b82f6',
  cyan: '#22d3ee',
  violet: '#8b5cf6',
  purple: '#a855f7',
  green: '#22c55e',
  amber: '#f59e0b',
  red: '#ef4444',
  neutral: '#64748b',
} as const

export const SEVERITY_HEX = {
  informational: '#7c8db3',
  low: '#22c55e',
  medium: '#eab308',
  high: '#f97316',
  critical: '#ef4444',
} as const

/** Categorical series colour ramp -- distinct hues at similar luminance so
 *  no slice reads as "more important" than another (see the project's
 *  dataviz palette guidance). Ordered for maximum adjacent contrast. */
export const CATEGORICAL = [
  '#3b82f6',
  '#8b5cf6',
  '#22d3ee',
  '#f59e0b',
  '#22c55e',
  '#ec4899',
  '#14b8a6',
  '#f97316',
] as const

export const CATEGORICAL_OTHER = '#475569'

/** Shared recharts chrome: axes, grid, tooltip surface. */
export const CHART = {
  axis: TEXT.muted,
  axisLine: 'rgba(120, 160, 255, 0.12)',
  grid: 'rgba(120, 160, 255, 0.08)',
  tooltipBg: 'rgba(11, 18, 32, 0.96)',
  tooltipBorder: LINE.strong,
  cursor: 'rgba(59, 130, 246, 0.10)',
} as const

/** Heatmap ramp, cold (unobserved) -> hot (heavily observed). Cell colour
 *  is picked by bucket rather than a continuous gradient so the legend can
 *  state exactly what each shade means. */
export const HEAT_RAMP = ['rgba(120, 160, 255, 0.05)', '#134e33', '#166534', '#ca8a04', '#ea580c', '#dc2626'] as const

export function heatColor(count: number): string {
  if (count <= 0) return HEAT_RAMP[0]
  if (count <= 2) return HEAT_RAMP[1]
  if (count <= 4) return HEAT_RAMP[2]
  if (count <= 6) return HEAT_RAMP[3]
  if (count <= 10) return HEAT_RAMP[4]
  return HEAT_RAMP[5]
}

export const HEAT_LEGEND = [
  { label: '0', color: HEAT_RAMP[0] },
  { label: '1-2', color: HEAT_RAMP[1] },
  { label: '3-4', color: HEAT_RAMP[2] },
  { label: '5-6', color: HEAT_RAMP[3] },
  { label: '7-10', color: HEAT_RAMP[4] },
  { label: '11+', color: HEAT_RAMP[5] },
] as const
