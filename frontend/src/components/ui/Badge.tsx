import clsx from 'clsx'
import type { ReactNode } from 'react'
import type { IncidentStatus, Severity } from '../../api'
import {
  SEVERITY_BG_SOFT_CLASSES,
  SEVERITY_BORDER_SOFT_CLASSES,
  SEVERITY_TEXT_CLASSES,
  severityLabel,
} from '../../lib/severity'
import { ACCENT_BG_SOFT, ACCENT_BORDER, ACCENT_TEXT, type Accent } from './accent'

/**
 * All pills in the app come from this one base: same geometry, same
 * uppercase micro type, only the colour channel changes. Severity, incident
 * status and log level each get a thin wrapper so call sites cannot invent
 * their own colour mapping.
 */

const BASE =
  'inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-micro font-semibold tracking-[0.08em] uppercase whitespace-nowrap'

export function Badge({
  children,
  accent = 'neutral',
  dot = false,
  className,
}: {
  children: ReactNode
  accent?: Accent
  dot?: boolean
  className?: string
}) {
  return (
    <span className={clsx(BASE, ACCENT_BG_SOFT[accent], ACCENT_TEXT[accent], ACCENT_BORDER[accent], className)}>
      {dot && <span className={clsx('h-1.5 w-1.5 rounded-full', accentDot(accent))} />}
      {children}
    </span>
  )
}

export function accentDot(accent: Accent): string {
  switch (accent) {
    case 'blue':
      return 'bg-accent-blue'
    case 'cyan':
      return 'bg-accent-cyan'
    case 'violet':
      return 'bg-accent-violet'
    case 'green':
      return 'bg-accent-green'
    case 'amber':
      return 'bg-accent-amber'
    case 'red':
      return 'bg-accent-red'
    default:
      return 'bg-text-muted'
  }
}

export function SeverityBadge({
  severity,
  score,
  dot = true,
  className,
}: {
  severity: Severity
  /** The 1-5 rank the label was derived from (base Sigma level + tactic
   *  weight) -- optional so call sites without it (e.g. rule definitions,
   *  which have no tactic-weighted score of their own) render unchanged. */
  score?: number | null
  dot?: boolean
  className?: string
}) {
  return (
    <span
      className={clsx(
        BASE,
        SEVERITY_BG_SOFT_CLASSES[severity],
        SEVERITY_TEXT_CLASSES[severity],
        SEVERITY_BORDER_SOFT_CLASSES[severity],
        className,
      )}
    >
      {dot && <span className={clsx('h-1.5 w-1.5 rounded-full', severityDot(severity))} />}
      {severityLabel(severity)}
      {score != null && <span className="font-mono opacity-70">· {score}/5</span>}
    </span>
  )
}

export function severityDot(severity: Severity): string {
  switch (severity) {
    case 'critical':
      return 'bg-severity-critical'
    case 'high':
      return 'bg-severity-high'
    case 'medium':
      return 'bg-severity-medium'
    case 'low':
      return 'bg-severity-low'
    default:
      return 'bg-severity-informational'
  }
}

// Incident status -> accent. Mirrors the backend ALLOWED_STATUSES set.
const STATUS_ACCENT: Record<IncidentStatus, Accent> = {
  open: 'blue',
  investigating: 'violet',
  resolved: 'green',
  closed: 'neutral',
}

const STATUS_LABEL: Record<IncidentStatus, string> = {
  open: 'Open',
  investigating: 'Investigating',
  resolved: 'Resolved',
  closed: 'Closed',
}

export function StatusBadge({ status, className }: { status: IncidentStatus; className?: string }) {
  return (
    <Badge accent={STATUS_ACCENT[status]} className={className}>
      {STATUS_LABEL[status]}
    </Badge>
  )
}

/** Log level, derived from an event alert severity (INFO when the event
 *  never matched a rule) -- the Logs vocabulary, not a second severity
 *  system. */
export type LogLevel = 'info' | 'warn' | 'error' | 'critical'

export function logLevelFor(severity: Severity | null, isAlert: boolean): LogLevel {
  if (!isAlert || severity === null) return 'info'
  if (severity === 'critical') return 'critical'
  if (severity === 'high') return 'error'
  if (severity === 'medium') return 'warn'
  return 'info'
}

export const LEVEL_ACCENT: Record<LogLevel, Accent> = {
  info: 'cyan',
  warn: 'amber',
  error: 'red',
  critical: 'red',
}

export function LevelBadge({ level, className }: { level: LogLevel; className?: string }) {
  return (
    <Badge accent={LEVEL_ACCENT[level]} className={clsx('justify-center', className)}>
      {level}
    </Badge>
  )
}

/** Live status dot + optional pulse. Tone is explicit so a caller cannot
 *  accidentally show green for a failing check. */
export function StatusDot({
  tone,
  pulse = true,
  className,
}: {
  tone: 'good' | 'warn' | 'bad' | 'idle'
  pulse?: boolean
  className?: string
}) {
  const color =
    tone === 'good'
      ? 'bg-accent-green'
      : tone === 'warn'
        ? 'bg-accent-amber'
        : tone === 'bad'
          ? 'bg-accent-red'
          : 'bg-text-muted'

  return (
    <span className={clsx('relative flex h-2 w-2 shrink-0', className)}>
      {pulse && tone !== 'idle' && (
        <span className={clsx('absolute inline-flex h-full w-full rounded-full opacity-60 animate-pulse-dot', color)} />
      )}
      <span className={clsx('relative inline-flex h-2 w-2 rounded-full', color)} />
    </span>
  )
}
