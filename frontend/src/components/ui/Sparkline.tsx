import { useId } from 'react'
import { ACCENT_HEX, type Accent } from './accent'

/**
 * Hand-drawn SVG sparkline -- recharts is overkill for a 60x26 trend line,
 * and its ResponsiveContainer measures the DOM on every render, which is
 * wasteful inside a KPI card that never resizes.
 *
 * Renders a soft gradient area under the stroke so the line reads at small
 * sizes without needing a heavier weight.
 */
export function Sparkline({
  data,
  accent = 'primary',
  width = 76,
  height = 28,
  className,
}: {
  data: number[]
  accent?: Accent
  width?: number
  height?: number
  className?: string
}) {
  const gradientId = useId()
  if (data.length < 2) return null

  const min = Math.min(...data)
  const max = Math.max(...data)
  const span = max - min || 1
  const stepX = width / (data.length - 1)
  const pad = 3

  const points = data.map((value, i) => {
    const x = i * stepX
    const y = height - pad - ((value - min) / span) * (height - pad * 2)
    return [x, y] as const
  })

  const line = points.map(([x, y], i) => `${i === 0 ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)}`).join(' ')
  const area = `${line} L${width},${height} L0,${height} Z`
  const color = ACCENT_HEX[accent]

  return (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      width={width}
      height={height}
      className={className}
      aria-hidden
      preserveAspectRatio="none"
    >
      <defs>
        <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.35" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <path d={area} fill={`url(#${gradientId})`} className="animate-rise" />
      {/* pathLength=1 normalises the path to one unit regardless of its real
          on-screen geometry, so the draw-in animation below needs no
          per-instance length calculation -- just dasharray/dashoffset 0-1. */}
      <path
        d={line}
        fill="none"
        stroke={color}
        strokeWidth="1.5"
        strokeLinejoin="round"
        strokeLinecap="round"
        pathLength={1}
        strokeDasharray={1}
        className="animate-draw"
        style={{ filter: `drop-shadow(0 0 3px ${color}70)` }}
      />
    </svg>
  )
}
