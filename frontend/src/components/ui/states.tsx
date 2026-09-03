import clsx from 'clsx'
import { AlertTriangle, Hourglass, Inbox, Loader2, RefreshCw } from 'lucide-react'
import { useEffect, useState, type ReactNode } from 'react'
import { isRateLimited } from '../../api'
import { Button } from './Button'

/**
 * The three async states every data surface in the app must handle. They
 * share one geometry so a panel does not visibly jump between loading,
 * empty and loaded.
 */

/**
 * Loading. The spinner sits inside its own soft violet bloom so a waiting
 * panel still looks like part of the environment rather than a blank hole.
 * Callers pass a contextual label ("Retrieving telemetry", "Mapping
 * techniques") rather than a bare "Loading".
 */
export function LoadingState({ label = 'Loading', className }: { label?: string; className?: string }) {
  return (
    <div
      className={clsx('flex flex-col items-center justify-center gap-2.5 px-4 py-10', className)}
      role="status"
      aria-live="polite"
    >
      <span className="relative flex h-9 w-9 items-center justify-center">
        <span aria-hidden className="absolute inset-0 rounded-full bg-accent-primary/20 blur-lg animate-glow-pulse" />
        <Loader2 className="relative h-5 w-5 animate-spin text-accent-violet" />
      </span>
      <span className="text-meta text-text-muted">{label}...</span>
    </div>
  )
}

/**
 * Empty state. Deliberately not a grey "No data": an empty SOC panel is
 * usually *good news*, so this is presented as a calm, lit statement with a
 * haloed icon and room for a reassuring hint ("Your environment is
 * currently clear") plus an optional next action.
 */
export function EmptyState({
  message,
  hint,
  icon,
  action,
  className,
}: {
  message: string
  hint?: string
  icon?: ReactNode
  action?: ReactNode
  className?: string
}) {
  return (
    <div className={clsx('relative flex flex-col items-center justify-center gap-2.5 px-4 py-12 text-center', className)}>
      {/* Ambient pool of light behind the icon -- the same lighting language
          as the rest of the app, at very low intensity. */}
      <span
        aria-hidden
        className="pointer-events-none absolute top-6 left-1/2 h-28 w-28 -translate-x-1/2 rounded-full bg-accent-primary/10 blur-2xl"
      />
      <span className="relative flex h-12 w-12 items-center justify-center rounded-full border border-line bg-surface-2/60 text-accent-violet/80 shadow-e2 backdrop-blur-md">
        {icon ?? <Inbox className="h-5 w-5" />}
      </span>
      <p className="relative text-body font-medium text-text-dim">{message}</p>
      {hint && <p className="relative max-w-sm text-meta leading-relaxed text-text-faint">{hint}</p>}
      {action && <div className="relative mt-1">{action}</div>}
    </div>
  )
}

/** Seconds to wait before retrying automatically after a 429. Long enough
 *  for the backend token bucket to refill more than a single page load
 *  needs, so the retry does not immediately re-drain it and bounce straight
 *  back into this state. */
const THROTTLE_RETRY_SECONDS = 20

export function ErrorState({
  message,
  onRetry,
  className,
}: {
  message: string
  onRetry?: () => void
  className?: string
}) {
  // Throttling is not a failure -- it is the API asking us to slow down, and
  // it clears on its own. It gets a calmer treatment and retries itself, so
  // the analyst is not sitting there clicking Retry into an empty bucket.
  if (isRateLimited(message)) return <ThrottledState message={message} onRetry={onRetry} className={className} />

  return (
    <div
      className={clsx('flex flex-col items-center justify-center gap-3 px-4 py-10 text-center', className)}
      role="alert"
    >
      <span className="flex h-10 w-10 items-center justify-center rounded-full bg-accent-red/12 text-accent-red">
        <AlertTriangle className="h-5 w-5" />
      </span>
      <div>
        <p className="text-body font-medium text-text">Something went wrong</p>
        <p className="mt-0.5 max-w-md text-meta text-text-muted">{message}</p>
      </div>
      {onRetry && (
        <Button size="sm" onClick={onRetry} icon={<RefreshCw className="h-3.5 w-3.5" />}>
          Retry
        </Button>
      )}
    </div>
  )
}

function ThrottledState({
  message,
  onRetry,
  className,
}: {
  message: string
  onRetry?: () => void
  className?: string
}) {
  const [secondsLeft, setSecondsLeft] = useState(THROTTLE_RETRY_SECONDS)

  useEffect(() => {
    if (!onRetry) return
    const timer = window.setInterval(() => {
      setSecondsLeft((current) => {
        if (current <= 1) {
          window.clearInterval(timer)
          onRetry()
          return 0
        }
        return current - 1
      })
    }, 1000)
    return () => window.clearInterval(timer)
  }, [onRetry])

  return (
    <div
      className={clsx('flex flex-col items-center justify-center gap-3 px-4 py-10 text-center', className)}
      role="status"
      aria-live="polite"
    >
      <span className="flex h-10 w-10 items-center justify-center rounded-full bg-accent-amber/12 text-accent-amber">
        <Hourglass className="h-5 w-5" />
      </span>
      <div>
        <p className="text-body font-medium text-text">Slowing down</p>
        <p className="mt-0.5 max-w-md text-meta text-text-muted">{message}</p>
      </div>
      {onRetry && (
        <div className="flex items-center gap-2">
          <span className="font-mono text-meta text-text-faint tabular-nums">
            Retrying in {secondsLeft}s
          </span>
          <Button size="sm" variant="ghost" onClick={onRetry} icon={<RefreshCw className="h-3.5 w-3.5" />}>
            Retry now
          </Button>
        </div>
      )}
    </div>
  )
}

/** Shimmering placeholder block. Callers size it to match the real content
 *  so the layout does not shift when data lands. */
export function Skeleton({ className }: { className?: string }) {
  return (
    <div className={clsx('relative overflow-hidden rounded-md bg-accent-primary/8', className)}>
      <span className="absolute inset-0 -translate-x-full animate-sweep bg-gradient-to-r from-transparent via-accent-primary/20 to-transparent" />
    </div>
  )
}

export function SkeletonRows({ rows = 5, className }: { rows?: number; className?: string }) {
  return (
    <div className={clsx('flex flex-col gap-2 p-4', className)}>
      {Array.from({ length: rows }).map((_, i) => (
        <Skeleton key={i} className="h-9 w-full" />
      ))}
    </div>
  )
}

export function SkeletonCard({ className }: { className?: string }) {
  return (
    <div className={clsx('rounded-card border border-line bg-surface-1/70 p-4', className)}>
      <Skeleton className="h-3 w-28" />
      <Skeleton className="mt-4 h-8 w-24" />
      <Skeleton className="mt-3 h-3 w-36" />
    </div>
  )
}
