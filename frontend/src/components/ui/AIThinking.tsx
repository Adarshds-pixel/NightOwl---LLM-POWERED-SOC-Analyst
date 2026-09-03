import clsx from 'clsx'
import { Brain, Check } from 'lucide-react'

/**
 * "The intelligence layer is working" -- a violet core with a breathing
 * halo, replacing the generic three bouncing dots.
 *
 * Two modes:
 *
 *  - label only (the default): one honest sentence about what is happening.
 *    Used by the chat, where a single POST /chat is in flight and there are
 *    no server-reported sub-steps to narrate.
 *
 *  - staged: pass `stages` + `activeIndex` to walk a list. Only use this
 *    where the caller genuinely has stage information. `useExplain`'s
 *    EXPLAIN_STAGES qualifies -- it narrates the retrieve -> draft ->
 *    self-critique work the explain endpoint really performs server-side,
 *    and is documented there as cosmetic timing over one real request.
 *    Do not invent stages for a call that has none.
 */
export function AIThinking({
  label = 'Reasoning',
  stages,
  activeIndex = 0,
  className,
}: {
  label?: string
  stages?: readonly string[]
  activeIndex?: number
  className?: string
}) {
  return (
    <div className={clsx('flex items-start gap-3', className)} role="status" aria-live="polite">
      <span className="relative flex h-8 w-8 shrink-0 items-center justify-center">
        {/* Two haloes on offset phases read as a slow pulse rather than a
            blink, and cost nothing but opacity/transform. */}
        <span aria-hidden className="absolute inset-0 rounded-full bg-accent-violet/25 blur-md animate-glow-pulse" />
        <span
          aria-hidden
          className="absolute inset-0 rounded-full border border-accent-violet/40 animate-glow-pulse"
          style={{ animationDelay: '1.1s' }}
        />
        <span className="relative flex h-8 w-8 items-center justify-center rounded-full border border-accent-violet/45 bg-surface-2/70 text-accent-violet">
          <Brain className="h-4 w-4" />
        </span>
      </span>

      {stages && stages.length > 0 ? (
        <ul className="flex min-w-0 flex-col gap-1 pt-1">
          {stages.map((stage, i) => {
            const done = i < activeIndex
            const current = i === activeIndex
            return (
              <li
                key={stage}
                className={clsx(
                  'flex items-center gap-2 text-meta transition-colors duration-300',
                  done ? 'text-text-muted' : current ? 'text-text-dim' : 'text-text-faint/60',
                )}
              >
                <span className="flex h-3.5 w-3.5 shrink-0 items-center justify-center">
                  {done ? (
                    <Check className="h-3 w-3 text-accent-primary" />
                  ) : current ? (
                    <span className="h-1.5 w-1.5 rounded-full bg-accent-violet animate-pulse-dot" />
                  ) : (
                    <span className="h-1.5 w-1.5 rounded-full bg-line-strong" />
                  )}
                </span>
                <span className="truncate">{stage}</span>
              </li>
            )
          })}
        </ul>
      ) : (
        <span className="pt-2 text-meta text-text-dim">
          {label}
          <span className="ml-0.5 inline-flex">
            {[0, 1, 2].map((i) => (
              <span
                key={i}
                className="animate-ai-pulse"
                style={{ animationDelay: `${i * 180}ms` }}
                aria-hidden
              >
                .
              </span>
            ))}
          </span>
        </span>
      )}
    </div>
  )
}
