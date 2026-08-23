import clsx from 'clsx'
import { ACCENT_STROKE_CLASSES, type Accent } from './accent'

interface RingGaugeProps {
  value: number
  label: string
  sublabel?: string
  accent?: Accent
  size?: number
}

const STROKE_WIDTH = 8

export function RingGauge({ value, label, sublabel, accent = 'cyan', size = 128 }: RingGaugeProps) {
  const clamped = Math.max(0, Math.min(100, value))
  const radius = (size - STROKE_WIDTH) / 2
  const circumference = 2 * Math.PI * radius
  const offset = circumference * (1 - clamped / 100)

  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          strokeWidth={STROKE_WIDTH}
          className="fill-none stroke-border"
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          strokeWidth={STROKE_WIDTH}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          className={clsx('fill-none transition-[stroke-dashoffset] duration-700', ACCENT_STROKE_CLASSES[accent])}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center px-2 text-center leading-tight">
        <span
          className="font-bold text-text uppercase"
          style={{ fontSize: Math.max(size * 0.15, 11) }}
        >
          {label}
        </span>
        {sublabel && (
          <span
            className="mt-1 text-text-muted uppercase"
            style={{ fontSize: Math.max(size * 0.085, 9) }}
          >
            {sublabel}
          </span>
        )}
      </div>
    </div>
  )
}
