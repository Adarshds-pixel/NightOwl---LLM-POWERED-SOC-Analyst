// recharts renders raw SVG and needs literal color values for reliable
// internal color computation (axis ticks, tooltip chrome, gradients) --
// same reasoning as SEVERITY_HEX in severity.ts. Keep these in sync by
// hand with src/index.css's @theme tokens (slate-400/slate-800/slate-900).
export const CHART_AXIS_COLOR = '#94a3b8' // text-muted / slate-400
export const CHART_GRID_COLOR = '#1e293b' // border / slate-800
export const CHART_TOOLTIP_BG = '#0f172a' // surface / slate-900
export const CHART_TOOLTIP_BORDER = '#1e293b' // border / slate-800

// Categorical palette for the attack-vector donut -- tactics aren't
// severity-ranked, so SEVERITY_HEX doesn't apply here. 7 distinct hues
// (top 6 + "Other"); revisit once Day 20's palette validator runs.
export const TACTIC_PALETTE = [
  '#22d3ee', // cyan-400
  '#a78bfa', // violet-400
  '#fbbf24', // amber-400
  '#34d399', // emerald-400
  '#fb923c', // orange-400
  '#f472b6', // pink-400
]
export const TACTIC_PALETTE_OTHER = '#64748b' // slate-500
