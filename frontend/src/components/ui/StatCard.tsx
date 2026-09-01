import clsx from 'clsx'
import { ArrowDownRight, ArrowUpRight, Minus } from 'lucide-react'
import type { ReactNode } from 'react'
import { usePreferences } from '../../context/preferences/usePreferences'
import { useCountUp } from '../../hooks/useCountUp'
import { formatCount } from '../../lib/format'
import { ACCENT_BORDER, ACCENT_CARD_SHADOW, type Accent } from './accent'
import { IconChip } from './Card'
import { Sparkline } from './Sparkline'

/**
 * The KPI card from the mockups: glowing circular icon, uppercase label,
 * one large metric, a real period-over-period delta and a trend sparkline.
 *
 * `delta` is deliberately nullable and rendered as an em dash when absent.
 * NightOwl only ever shows a change figure it can actually compute from
 * ingested timestamps -- a KPI with no comparable previous window says so
 * instead of inventing a percentage.
 */

export interface StatDelta {
  /** Signed percentage change vs the previous window. */
  percent: number
  /** What the comparison window was, e.g. "vs previous 24h". */
  label: string
  /** True when a rise is bad (incidents up = worse). Drives colour only. */
  riseIsBad?: boolean
}

interface StatCardProps {
  label: string
  value: number
  icon: ReactNode
  accent?: Accent
  delta?: StatDelta | null
  trend?: number[]
  /** Replaces the delta line, for metrics with no time dimension. */
  note?: string
  /** Renders the (count-up animated) value. Defaults to formatCount, which
   *  is integer-only -- pass this for a metric that isn't a plain count,
   *  e.g. a percentage. */
  format?: (value: number) => string
  onClick?: () => void
  className?: string
}

export function StatCard({
  label,
  value,
  icon,
  accent = 'blue',
  delta,
  trend,
  note,
  format,
  onClick,
  className,
}: StatCardProps) {
  const { prefs } = usePreferences()
  const animated = useCountUp(value, prefs.animatedCounters)
  const Wrapper = onClick ? 'button' : 'div'

  return (
    <Wrapper
      {...(onClick ? { type: 'button' as const, onClick } : {})}
      className={clsx(
        'group relative flex min-w-0 flex-col overflow-hidden rounded-card border bg-surface-1/70 bg-gradient-to-b from-white/[0.035] to-transparent px-4 py-3.5 text-left backdrop-blur-[4px] transition-colors duration-200',
        ACCENT_BORDER[accent],
        ACCENT_CARD_SHADOW[accent],
        onClick && 'hover:border-line-strong',
        className,
      )}
    >
      <span aria-hidden className={clsx('pointer-events-none absolute -top-16 -left-10 h-32 w-40 rounded-full opacity-60 blur-2xl', glowClass(accent))} />

      <div className="relative flex items-start gap-3">
        <IconChip icon={icon} accent={accent} />
        <div className="min-w-0 flex-1">
          <p className="truncate text-micro font-semibold tracking-[0.14em] text-text-muted uppercase">{label}</p>
          <div className="mt-1 flex items-end justify-between gap-3">
            <span className="font-mono text-metric leading-none font-semibold tracking-tight text-text tabular-nums">
              {format ? format(animated) : formatCount(animated)}
            </span>
            {trend && trend.length > 1 && <Sparkline data={trend} accent={accent} className="mb-0.5 shrink-0" />}
          </div>
        </div>
      </div>

      <div className="relative mt-3 flex items-center gap-1.5 text-micro">
        {note ? (
          <span className="text-text-faint">{note}</span>
        ) : delta ? (
          <DeltaLine delta={delta} />
        ) : (
          <span className="text-text-faint">Not enough history to compare</span>
        )}
      </div>
    </Wrapper>
  )
}

function DeltaLine({ delta }: { delta: StatDelta }) {
  const flat = Math.abs(delta.percent) < 0.5
  const up = delta.percent > 0
  const bad = delta.riseIsBad ?? true
  const tone = flat ? 'text-text-muted' : up === bad ? 'text-severity-high' : 'text-severity-low'
  const Icon = flat ? Minus : up ? ArrowUpRight : ArrowDownRight

  return (
    <>
      <span className={clsx('flex items-center gap-0.5 font-semibold', tone)}>
        <Icon className="h-3 w-3" />
        {flat ? 'no change' : `${Math.abs(Math.round(delta.percent))}%`}
      </span>
      <span className="truncate text-text-faint">{delta.label}</span>
    </>
  )
}

function glowClass(accent: Accent): string {
  switch (accent) {
    case 'blue':
      return 'bg-accent-blue/20'
    case 'cyan':
      return 'bg-accent-cyan/20'
    case 'violet':
      return 'bg-accent-violet/20'
    case 'green':
      return 'bg-accent-green/20'
    case 'amber':
      return 'bg-accent-amber/20'
    case 'red':
      return 'bg-accent-red/20'
    default:
      return 'bg-white/5'
  }
}
