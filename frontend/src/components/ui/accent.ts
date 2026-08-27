/**
 * Accent = the "channel" a surface belongs to: blue for neutral/technical,
 * violet for every AI/RAG surface, green/amber/red echoing severity, cyan
 * for telemetry. Components take an `accent` prop and look their classes up
 * here rather than composing class names.
 *
 * These are full literal class strings on purpose: Tailwind's scanner only
 * sees complete class names in source, so `bg-accent-${x}` would silently
 * produce no CSS. Every new accent-varying utility must be added as a
 * complete string to one of these maps (same rule as lib/severity.ts).
 */

export type Accent = 'blue' | 'cyan' | 'violet' | 'green' | 'amber' | 'red' | 'neutral'

export const ACCENT_TEXT: Record<Accent, string> = {
  blue: 'text-accent-blue',
  cyan: 'text-accent-cyan',
  violet: 'text-accent-violet',
  green: 'text-accent-green',
  amber: 'text-accent-amber',
  red: 'text-accent-red',
  neutral: 'text-text-dim',
}

export const ACCENT_BG_SOFT: Record<Accent, string> = {
  blue: 'bg-accent-blue/12',
  cyan: 'bg-accent-cyan/12',
  violet: 'bg-accent-violet/12',
  green: 'bg-accent-green/12',
  amber: 'bg-accent-amber/12',
  red: 'bg-accent-red/12',
  neutral: 'bg-white/5',
}

export const ACCENT_BG_SOLID: Record<Accent, string> = {
  blue: 'bg-accent-blue',
  cyan: 'bg-accent-cyan',
  violet: 'bg-accent-violet',
  green: 'bg-accent-green',
  amber: 'bg-accent-amber',
  red: 'bg-accent-red',
  neutral: 'bg-text-muted',
}

export const ACCENT_BORDER: Record<Accent, string> = {
  blue: 'border-accent-blue/30',
  cyan: 'border-accent-cyan/30',
  violet: 'border-accent-violet/30',
  green: 'border-accent-green/30',
  amber: 'border-accent-amber/30',
  red: 'border-accent-red/30',
  neutral: 'border-line',
}

export const ACCENT_RING: Record<Accent, string> = {
  blue: 'ring-accent-blue/25',
  cyan: 'ring-accent-cyan/25',
  violet: 'ring-accent-violet/25',
  green: 'ring-accent-green/25',
  amber: 'ring-accent-amber/25',
  red: 'ring-accent-red/25',
  neutral: 'ring-white/10',
}

export const ACCENT_GLOW: Record<Accent, string> = {
  blue: 'shadow-glow-blue',
  cyan: 'shadow-glow-cyan',
  violet: 'shadow-glow-violet',
  green: 'shadow-glow-green',
  amber: 'shadow-glow-amber',
  red: 'shadow-glow-red',
  neutral: '',
}

export const ACCENT_HEX: Record<Accent, string> = {
  blue: '#3b82f6',
  cyan: '#22d3ee',
  violet: '#8b5cf6',
  green: '#22c55e',
  amber: '#f59e0b',
  red: '#ef4444',
  neutral: '#64748b',
}
