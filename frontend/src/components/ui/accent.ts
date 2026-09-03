/**
 * Accent = the "channel" a surface belongs to: `primary` (violet) for
 * neutral/technical, `violet` (electric purple) for every AI/RAG surface,
 * `magenta` for telemetry and live feeds, amber/red echoing severity, and
 * `green` reserved for genuine success states only -- never as a UI theme
 * colour. Components take an `accent` prop and look their classes up here
 * rather than composing class names.
 *
 * Channels are named for their role's hue in the current palette. When the
 * palette moves, these values move with it and the call sites do not: that is
 * the whole point of routing every tint through this one file.
 *
 * These are full literal class strings on purpose: Tailwind's scanner only
 * sees complete class names in source, so `bg-accent-${x}` would silently
 * produce no CSS. Every new accent-varying utility must be added as a
 * complete string to one of these maps (same rule as lib/severity.ts).
 */

import { ACCENT } from '../../lib/tokens'

export type Accent = 'primary' | 'magenta' | 'violet' | 'green' | 'amber' | 'orange' | 'red' | 'neutral'

export const ACCENT_TEXT: Record<Accent, string> = {
  primary: 'text-accent-primary',
  magenta: 'text-accent-magenta',
  violet: 'text-accent-violet',
  green: 'text-accent-green',
  amber: 'text-accent-amber',
  orange: 'text-accent-orange',
  red: 'text-accent-red',
  neutral: 'text-text-dim',
}

export const ACCENT_BG_SOFT: Record<Accent, string> = {
  primary: 'bg-accent-primary/12',
  magenta: 'bg-accent-magenta/12',
  violet: 'bg-accent-violet/12',
  green: 'bg-accent-green/12',
  amber: 'bg-accent-amber/12',
  orange: 'bg-accent-orange/12',
  red: 'bg-accent-red/12',
  neutral: 'bg-white/5',
}

export const ACCENT_BG_SOLID: Record<Accent, string> = {
  primary: 'bg-accent-primary',
  magenta: 'bg-accent-magenta',
  violet: 'bg-accent-violet',
  green: 'bg-accent-green',
  amber: 'bg-accent-amber',
  orange: 'bg-accent-orange',
  red: 'bg-accent-red',
  neutral: 'bg-text-muted',
}

export const ACCENT_BORDER: Record<Accent, string> = {
  primary: 'border-accent-primary/30',
  magenta: 'border-accent-magenta/30',
  violet: 'border-accent-violet/30',
  green: 'border-accent-green/30',
  amber: 'border-accent-amber/30',
  orange: 'border-accent-orange/30',
  red: 'border-accent-red/30',
  neutral: 'border-line',
}

export const ACCENT_RING: Record<Accent, string> = {
  primary: 'ring-accent-primary/25',
  magenta: 'ring-accent-magenta/25',
  violet: 'ring-accent-violet/25',
  green: 'ring-accent-green/25',
  amber: 'ring-accent-amber/25',
  orange: 'ring-accent-orange/25',
  red: 'ring-accent-red/25',
  neutral: 'ring-white/10',
}

export const ACCENT_GLOW: Record<Accent, string> = {
  primary: 'shadow-glow-primary',
  magenta: 'shadow-glow-magenta',
  violet: 'shadow-glow-violet',
  green: 'shadow-glow-green',
  amber: 'shadow-glow-amber',
  orange: 'shadow-glow-orange',
  red: 'shadow-glow-red',
  neutral: '',
}

/** Card-scale version of ACCENT_GLOW: ambient lift + accent bloom combined
 * into one shadow value, since a card can only carry one `box-shadow`. */
export const ACCENT_CARD_SHADOW: Record<Accent, string> = {
  primary: 'shadow-card-primary',
  magenta: 'shadow-card-magenta',
  violet: 'shadow-card-violet',
  green: 'shadow-card-green',
  amber: 'shadow-card-amber',
  orange: 'shadow-card-orange',
  red: 'shadow-card-red',
  neutral: 'shadow-card',
}

/** Faint top-edge wash used by KPI/metric cards, so a card reads as lit from
 *  its own channel rather than uniformly grey. Kept very low-opacity: the
 *  brief asks for selective glow, not a glowing wall. */
export const ACCENT_GRADIENT: Record<Accent, string> = {
  primary: 'from-accent-primary/[0.10]',
  magenta: 'from-accent-magenta/[0.10]',
  violet: 'from-accent-violet/[0.10]',
  green: 'from-accent-green/[0.08]',
  amber: 'from-accent-amber/[0.08]',
  orange: 'from-accent-orange/[0.08]',
  red: 'from-accent-red/[0.10]',
  neutral: 'from-white/[0.035]',
}

/** Re-exported from lib/tokens.ts rather than copied, so a palette change
 *  can never leave the class maps above and the raw hexes disagreeing. */
export const ACCENT_HEX: Record<Accent, string> = {
  primary: ACCENT.primary,
  magenta: ACCENT.magenta,
  violet: ACCENT.violet,
  green: ACCENT.green,
  amber: ACCENT.amber,
  orange: ACCENT.orange,
  red: ACCENT.red,
  neutral: ACCENT.neutral,
}
