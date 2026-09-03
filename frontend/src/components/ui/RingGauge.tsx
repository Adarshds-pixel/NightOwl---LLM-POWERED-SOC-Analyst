import clsx from 'clsx'
import { useEffect, useState } from 'react'
import { LINE } from '../../lib/tokens'
import { ACCENT_HEX, type Accent } from './accent'

/**
 * Circular progress ring with a value in the middle -- the Pipeline Health
 * gauges and the sidebar threat level. Pure SVG (stroke-dasharray), no
 * chart library: it is one arc and a label.
 *
 * The arc uses `pathLength={1}` to normalise its own length to one unit
 * regardless of the real on-screen radius, so a 0-100 value maps straight
 * onto a 0-1 stroke-dashoffset with no circumference maths. On mount the
 * offset starts at "empty" and moves to its target one animation frame
 * later, so the ring draws in rather than appearing already full -- CSS
 * transitions only animate a *change*, not an initial value, hence the
 * `mounted` flag. Every later value change reuses the same transition.
 */
export function RingGauge({
  value,
  label,
  sublabel,
  accent = 'primary',
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
  const color = ACCENT_HEX[accent]

  const [mounted, setMounted] = useState(false)
  useEffect(() => {
    const frame = requestAnimationFrame(() => setMounted(true))
    return () => cancelAnimationFrame(frame)
  }, [])
  const offset = mounted ? 1 - clamped / 100 : 1

  return (
    <div className={clsx('flex flex-col items-center gap-1.5', className)}>
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="-rotate-90" role="img" aria-label={`${label ?? 'Value'}: ${clamped}${unit}`}>
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={LINE.base}
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
            pathLength={1}
            strokeDasharray={1}
            strokeDashoffset={offset}
            style={{
              transition: 'stroke-dashoffset 700ms cubic-bezier(0.22, 0.61, 0.36, 1)',
              filter: `drop-shadow(0 0 4px ${color}55)`,
            }}
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
