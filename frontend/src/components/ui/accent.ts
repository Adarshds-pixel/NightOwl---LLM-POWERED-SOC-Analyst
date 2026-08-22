export type Accent = 'cyan' | 'red' | 'amber' | 'green' | 'purple' | 'neutral'

// Full class strings, not template-literal interpolation -- Tailwind's JIT
// scanner only detects complete literal class names in source (see
// src/lib/severity.ts for the same pattern already established there).
export const ACCENT_BORDER_CLASSES: Record<Accent, string> = {
  cyan: 'border-accent-cyan',
  red: 'border-accent-red',
  amber: 'border-accent-amber',
  green: 'border-accent-green',
  purple: 'border-accent-purple',
  neutral: 'border-border',
}

// Dimmer frame for Panel's own border, so HudCorners' full-opacity brackets
// read as a distinct "lit corner" accent rather than just a thicker border.
export const ACCENT_BORDER_SOFT_CLASSES: Record<Accent, string> = {
  cyan: 'border-accent-cyan/30',
  red: 'border-accent-red/30',
  amber: 'border-accent-amber/30',
  green: 'border-accent-green/30',
  purple: 'border-accent-purple/30',
  neutral: 'border-border',
}

export const ACCENT_TEXT_CLASSES: Record<Accent, string> = {
  cyan: 'text-accent-cyan',
  red: 'text-accent-red',
  amber: 'text-accent-amber',
  green: 'text-accent-green',
  purple: 'text-accent-purple',
  neutral: 'text-text-muted',
}

export const ACCENT_STROKE_CLASSES: Record<Accent, string> = {
  cyan: 'stroke-accent-cyan',
  red: 'stroke-accent-red',
  amber: 'stroke-accent-amber',
  green: 'stroke-accent-green',
  purple: 'stroke-accent-purple',
  neutral: 'stroke-text-muted',
}

export const ACCENT_GLOW_CLASSES: Record<Accent, string> = {
  cyan: 'shadow-glow-cyan',
  red: 'shadow-glow-red',
  amber: 'shadow-glow-amber',
  green: 'shadow-glow-green',
  purple: 'shadow-glow-purple',
  neutral: '',
}

// Soft translucent fills for icon boxes/badge backgrounds -- Tailwind v4's
// `/10` opacity modifier works on any color utility, so this needs its own
// literal map rather than string-concatenating onto ACCENT_BG_CLASSES.
export const ACCENT_BG_SOFT_CLASSES: Record<Accent, string> = {
  cyan: 'bg-accent-cyan/10',
  red: 'bg-accent-red/10',
  amber: 'bg-accent-amber/10',
  green: 'bg-accent-green/10',
  purple: 'bg-accent-purple/10',
  neutral: 'bg-border/40',
}

export const ACCENT_DOT_CLASSES: Record<Accent, string> = {
  cyan: 'bg-accent-cyan',
  red: 'bg-accent-red',
  amber: 'bg-accent-amber',
  green: 'bg-accent-green',
  purple: 'bg-accent-purple',
  neutral: 'bg-text-muted',
}
