import { ACCENT_STROKE_CLASSES, type Accent } from './accent'

interface SparklineProps {
  data: number[]
  accent?: Accent
  width?: number
  height?: number
}

export function Sparkline({ data, accent = 'cyan', width = 64, height = 24 }: SparklineProps) {
  if (data.length < 2) return null

  const min = Math.min(...data)
  const max = Math.max(...data)
  const range = max - min || 1

  const points = data
    .map((value, i) => {
      const x = (i / (data.length - 1)) * width
      const y = height - ((value - min) / range) * height
      return `${x},${y}`
    })
    .join(' ')

  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} className="overflow-visible">
      <polyline
        points={points}
        className={`fill-none stroke-2 ${ACCENT_STROKE_CLASSES[accent]}`}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}
