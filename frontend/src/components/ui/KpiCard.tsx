import clsx from 'clsx'
import type { ReactNode } from 'react'
import { useCountUp } from '../../hooks/useCountUp'
import { ACCENT_BG_SOFT_CLASSES, ACCENT_TEXT_CLASSES, type Accent } from './accent'
import { Panel } from './Panel'
import { Sparkline } from './Sparkline'

interface KpiCardTrend {
  direction: 'up' | 'down'
  percent: number
}

interface KpiCardProps {
  label: string
  value: number
  icon?: ReactNode
  accent?: Accent
  trend?: KpiCardTrend
  sparkline?: number[]
}

export function KpiCard({ label, value, icon, accent = 'cyan', trend, sparkline }: KpiCardProps) {
  const animated = useCountUp(value)

  return (
    <Panel accent={accent} className="flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          {icon && (
            <span className={clsx('flex h-7 w-7 items-center justify-center rounded', ACCENT_BG_SOFT_CLASSES[accent])}>
              <span className={ACCENT_TEXT_CLASSES[accent]}>{icon}</span>
            </span>
          )}
          <span className="text-xs font-medium tracking-widest text-text-muted uppercase">{label}</span>
        </div>
        {sparkline && sparkline.length > 1 && <Sparkline data={sparkline} accent={accent} />}
      </div>

      <div className="flex items-baseline gap-2">
        <span className="font-display text-3xl font-bold tracking-tight text-text tabular-nums">
          {animated.toLocaleString()}
        </span>
        {trend && (
          <span
            className={clsx(
              'text-xs font-semibold',
              trend.direction === 'up' ? 'text-severity-high' : 'text-severity-low',
            )}
          >
            {trend.direction === 'up' ? '↑' : '↓'} {trend.percent}%
          </span>
        )}
      </div>
    </Panel>
  )
}
