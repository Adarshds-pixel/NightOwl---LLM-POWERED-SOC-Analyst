import clsx from 'clsx'
import { ChevronRight } from 'lucide-react'
import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import type { Severity } from '../../api'
import { SEVERITY_HEX } from '../../lib/severity'
import { severityDot } from './Badge'

/**
 * The dense list rows the mockups use inside cards (recent alerts, active
 * incidents, top rules, recent conversations). They are list items, not
 * tables: no column headers, a severity marker on the left, a timestamp on
 * the right, everything else truncating in between.
 */

export function ListRow({
  to,
  onClick,
  marker,
  title,
  meta,
  trailing,
  className,
}: {
  to?: string
  onClick?: () => void
  marker?: ReactNode
  title: ReactNode
  meta?: ReactNode
  trailing?: ReactNode
  className?: string
}) {
  const content = (
    <>
      {marker && <span className="mt-0.5 flex shrink-0 items-center">{marker}</span>}
      <span className="min-w-0 flex-1">
        <span className="block truncate text-body text-text-dim group-hover/row:text-text">{title}</span>
        {meta && <span className="mt-0.5 block truncate text-micro text-text-faint">{meta}</span>}
      </span>
      {trailing && <span className="flex shrink-0 items-center gap-2">{trailing}</span>}
    </>
  )

  const classes = clsx(
    'group/row flex w-full items-start gap-2.5 rounded-control px-2.5 py-2 text-left transition-colors duration-150 hover:bg-white/4',
    className,
  )

  if (to) {
    return (
      <Link to={to} className={classes}>
        {content}
      </Link>
    )
  }

  return onClick ? (
    <button type="button" onClick={onClick} className={classes}>
      {content}
    </button>
  ) : (
    <div className={classes}>{content}</div>
  )
}

export function SeverityDotMarker({ severity }: { severity: Severity }) {
  return <span className={clsx('h-2 w-2 rounded-full', severityDot(severity))} />
}

/** Vertical event timeline (incident audit trail, incident detail). */
export function Timeline({ children, className }: { children: ReactNode; className?: string }) {
  return <ol className={clsx('relative flex flex-col gap-3 pl-4', className)}>{children}</ol>
}

export function TimelineItem({
  title,
  timestamp,
  detail,
  severity,
  accentColor,
}: {
  title: ReactNode
  timestamp?: ReactNode
  detail?: ReactNode
  severity?: Severity
  accentColor?: string
}) {
  const color = accentColor ?? (severity ? SEVERITY_HEX[severity] : '#3b82f6')
  return (
    <li className="relative pl-4">
      <span
        aria-hidden
        className="absolute top-1.5 left-0 h-2 w-2 rounded-full ring-4 ring-surface-1"
        style={{ background: color }}
      />
      <span aria-hidden className="absolute top-4 bottom-[-0.75rem] left-[3px] w-px bg-line last:hidden" />
      <div className="flex items-baseline justify-between gap-3">
        <span className="text-body text-text-dim">{title}</span>
        {timestamp && <span className="shrink-0 font-mono text-micro text-text-faint tabular-nums">{timestamp}</span>}
      </div>
      {detail && <div className="mt-1 text-meta text-text-muted">{detail}</div>}
    </li>
  )
}

/** Label/value pair used inside detail panels and stat strips. */
export function KeyValue({
  label,
  value,
  className,
  mono = false,
}: {
  label: ReactNode
  value: ReactNode
  className?: string
  mono?: boolean
}) {
  return (
    <div className={clsx('min-w-0', className)}>
      <dt className="text-micro font-medium tracking-[0.1em] text-text-faint uppercase">{label}</dt>
      <dd className={clsx('mt-0.5 truncate text-body text-text-dim', mono && 'font-mono tabular-nums')}>{value}</dd>
    </div>
  )
}

/** Small "View all" affordance in card headers. */
export function ViewAllLink({ to, label = 'View all' }: { to: string; label?: string }) {
  return (
    <Link
      to={to}
      className="flex items-center gap-0.5 text-micro font-semibold tracking-wide text-accent-blue uppercase transition-colors hover:text-accent-cyan"
    >
      {label}
      <ChevronRight className="h-3 w-3" />
    </Link>
  )
}

/** Compact stat used inside panels (never a full StatCard). */
export function MiniStat({
  label,
  value,
  note,
  className,
}: {
  label: string
  value: ReactNode
  note?: ReactNode
  className?: string
}) {
  return (
    <div className={clsx('rounded-control border border-line bg-surface-2/40 px-3 py-2', className)}>
      <p className="text-micro font-medium tracking-[0.1em] text-text-faint uppercase">{label}</p>
      <p className="mt-1 font-mono text-title font-semibold text-text tabular-nums">{value}</p>
      {note && <p className="mt-0.5 text-micro text-text-faint">{note}</p>}
    </div>
  )
}
