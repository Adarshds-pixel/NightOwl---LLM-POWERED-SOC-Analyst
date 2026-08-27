import clsx from 'clsx'
import { ACCENT_HEX, type Accent } from './accent'

/**
 * The little ECG line in the sidebar status block. Deterministic polyline,
 * animated only by a slow horizontal sweep, so it reads as "system alive"
 * without pretending to plot data it does not have.
 */
export function ActivityIndicator({
  accent = 'green',
  active = true,
  width = 56,
  height = 20,
  className,
}: {
  accent?: Accent
  active?: boolean
  width?: number
  height?: number
  className?: string
}) {
  const color = active ? ACCENT_HEX[accent] : ACCENT_HEX.neutral
  const mid = height / 2
  const path = `M0,${mid} L${width * 0.18},${mid} L${width * 0.26},${mid - 6} L${width * 0.34},${mid + 5} L${width * 0.42},${mid} L${width * 0.62},${mid} L${width * 0.7},${mid - 4} L${width * 0.78},${mid + 3} L${width * 0.86},${mid} L${width},${mid}`

  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} className={clsx('overflow-visible', className)} aria-hidden>
      <path d={path} fill="none" stroke={color} strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" opacity={active ? 1 : 0.5} />
    </svg>
  )
}

/** Three-dot typing indicator for the AI surfaces. */
export function TypingDots({ className }: { className?: string }) {
  return (
    <span className={clsx('inline-flex items-center gap-1', className)} aria-label="Assistant is responding">
      {[0, 1, 2].map((i) => (
        <span
          key={i}
          className="h-1.5 w-1.5 rounded-full bg-accent-violet animate-pulse-dot"
          style={{ animationDelay: `${i * 160}ms` }}
        />
      ))}
    </span>
  )
}
