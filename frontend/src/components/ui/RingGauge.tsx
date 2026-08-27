import clsx from 'clsx'
import { ACCENT_HEX, type Accent } from './accent'

/**
 * Circular progress ring with a value in the middle -- the Pipeline Health
 * gauges and the sidebar threat level. Pure SVG (stroke-dasharray), no
 * chart library: it is one arc and a label.
 */
export function RingGauge({
  value,
  label,
  sublabel,
  accent = 'blue',
  size = 74,
  thickness = 5,
  unit = '%',
  className,
}: {
  /** 0-100. Values outside the range are clamped, never wrapped. */
  value: number
  label?: string
  sublabel?: string
  accent?: Accent
  size?: number
  thickness?: number
  unit?: string
  className?: string
}) {
  const clamped = Math.max(0, Math.min(100, value))
  const radius = (size - thickness) / 2
  const circumference = 2 * Math.PI * radius
  const dash = (clamped / 100) * circumference
  const color = ACCENT_HEX[accent]

  return (
    <div className={clsx('flex flex-col items-center gap-1.5', className)}>
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="-rotate-90" role="img" aria-label={`${label ?? 'Value'}: ${clamped}${unit}`}>
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke="rgba(120, 160, 255, 0.10)"
            strokeWidth={thickness}
          />
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth={thickness}
            strokeLinecap="round"
            strokeDasharray={`${dash} ${circumference - dash}`}
            style={{ transition: 'stroke-dasharray 400ms ease-out', filter: `drop-shadow(0 0 4px ${color}55)` }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="font-mono text-title leading-none font-semibold text-text tabular-nums">
            {Math.round(clamped)}
            <span className="text-micro text-text-muted">{unit}</span>
          </span>
        </div>
      </div>
      {label && <span className="text-micro font-semibold tracking-[0.12em] text-text-muted uppercase">{label}</span>}
      {sublabel && <span className="text-micro text-text-faint">{sublabel}</span>}
    </div>
  )
}

/** Thin horizontal meter for inline percentages (technique coverage, rule
 *  category shares) where a ring would be too heavy. */
export function MeterBar({
  value,
  max = 100,
  color,
  className,
}: {
  value: number
  max?: number
  color: string
  className?: string
}) {
  const pct = max > 0 ? Math.max(0, Math.min(100, (value / max) * 100)) : 0
  return (
    <div className={clsx('h-1.5 w-full overflow-hidden rounded-full bg-white/6', className)}>
      <div
        className="h-full rounded-full transition-[width] duration-500"
        style={{ width: `${pct}%`, background: color, boxShadow: `0 0 8px ${color}66` }}
      />
    </div>
  )
}
