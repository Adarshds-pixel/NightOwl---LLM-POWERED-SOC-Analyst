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
  bg: '#05030a',
  bgDeep: '#030108',
  surface: '#0b0715',
  surface1: '#0f091c',
  surface2: '#170e2d',
  surface3: '#23123a',
  elevated: '#1a0f2e',
} as const

export const LINE = {
  soft: 'rgba(139, 92, 246, 0.10)',
  base: 'rgba(139, 92, 246, 0.18)',
  strong: 'rgba(168, 85, 247, 0.38)',
} as const

export const TEXT = {
  base: '#f5f3ff',
  dim: '#c4b5fd',
  muted: '#8b849d',
  faint: '#6b647d',
} as const

export const ACCENT = {
  primary: '#8b5cf6',
  magenta: '#ec4899',
  violet: '#a855f7',
  pink: '#f472b6',
  green: '#22c55e',
  amber: '#f59e0b',
  orange: '#f97316',
  red: '#ef4444',
  neutral: '#8b849d',
} as const

/** Severity ramp. Low is lavender, not green: green would read as "healthy"
 *  and collide with the violet UI chrome. Warm hues stay reserved for the
 *  genuinely urgent end of the scale. */
export const SEVERITY_HEX = {
  informational: '#8b849d',
  low: '#a78bfa',
  medium: '#f59e0b',
  high: '#f97316',
  critical: '#ef4444',
} as const

/** Categorical series colour ramp -- MITRE tactics are genuinely distinct
 *  categories, so multiple hues are warranted here, but they stay inside the
 *  violet/magenta brand family (with two warm outliers for separation) so a
 *  donut never turns into a rainbow. Ordered for maximum adjacent contrast. */
export const CATEGORICAL = [
  '#8b5cf6',
  '#ec4899',
  '#a855f7',
  '#f472b6',
  '#7c3aed',
  '#f59e0b',
  '#c084fc',
  '#f97316',
] as const

export const CATEGORICAL_OTHER = '#4b4459'

/** Shared recharts chrome: axes, grid, tooltip surface. */
export const CHART = {
  axis: TEXT.muted,
  axisLine: 'rgba(139, 92, 246, 0.20)',
  grid: 'rgba(139, 92, 246, 0.12)',
  tooltipBg: 'rgba(15, 9, 28, 0.96)',
  tooltipBorder: LINE.strong,
  cursor: 'rgba(139, 92, 246, 0.14)',
} as const

/** Heatmap ramp, cold (unobserved) -> hot (heavily observed): charcoal into
 *  deep violet, through electric purple and magenta, ending at severity red.
 *  Cell colour is picked by bucket rather than a continuous gradient so the
 *  legend can state exactly what each shade means. */
export const HEAT_RAMP = ['#171226', '#4c1d95', '#6d28d9', '#9333ea', '#ec4899', '#ef4444'] as const

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
