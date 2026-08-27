import clsx from 'clsx'
import type { ReactNode } from 'react'
import { ACCENT_BG_SOFT, ACCENT_TEXT, type Accent } from './accent'

/**
 * The surface every panel in NightOwl is built on: a translucent navy card
 * with a single hairline border, an inner top highlight and a soft ambient
 * shadow (never a heavy drop shadow or a heavy blur -- the mockups read as
 * lit glass, not frosted plastic).
 *
 * `accent` tints the title and the optional icon chip only. The card body
 * itself stays neutral, so a page of eight cards does not turn into eight
 * competing colours.
 */

interface CardProps {
  title?: ReactNode
  /** Small uppercase text under the title, e.g. "By MITRE tactic". */
  subtitle?: ReactNode
  icon?: ReactNode
  accent?: Accent
  /** Right-hand slot in the header: "View all", filters, a badge. */
  action?: ReactNode
  /** Hairline under the header -- used by table cards, not chart cards. */
  divided?: boolean
  /** Removes body padding, for tables that manage their own insets. */
  flush?: boolean
  className?: string
  bodyClassName?: string
  children?: ReactNode
}

export function Card({
  title,
  subtitle,
  icon,
  accent = 'blue',
  action,
  divided = false,
  flush = false,
  className,
  bodyClassName,
  children,
}: CardProps) {
  return (
    <section
      className={clsx(
        'relative flex min-w-0 flex-col rounded-card border border-line bg-surface-1/70 shadow-card backdrop-blur-[2px]',
        className,
      )}
    >
      {(title || action) && (
        <header
          className={clsx(
            'flex shrink-0 items-start justify-between gap-3 px-4 pt-3.5',
            divided ? 'border-b border-line-soft pb-3' : 'pb-2',
          )}
        >
          <div className="flex min-w-0 items-center gap-2">
            {icon && (
              <span
                className={clsx(
                  'flex h-6 w-6 shrink-0 items-center justify-center rounded-chip',
                  ACCENT_BG_SOFT[accent],
                  ACCENT_TEXT[accent],
                )}
              >
                {icon}
              </span>
            )}
            <div className="min-w-0">
              {title && (
                <h2 className="truncate text-meta font-semibold tracking-[0.12em] text-text-dim uppercase">{title}</h2>
              )}
              {subtitle && <p className="truncate text-micro text-text-faint">{subtitle}</p>}
            </div>
          </div>
          {action && <div className="flex shrink-0 items-center gap-2">{action}</div>}
        </header>
      )}
      <div className={clsx('min-w-0 flex-1', flush ? '' : 'px-4 pt-1 pb-4', bodyClassName)}>{children}</div>
    </section>
  )
}

/**
 * Circular glowing icon container -- the mockups KPI/statistic marker.
 * Sized in three steps so a KPI card, a card header and a list row can all
 * use the same component without ad-hoc sizing at the call site.
 */
export function IconChip({
  icon,
  accent = 'blue',
  size = 'md',
  className,
}: {
  icon: ReactNode
  accent?: Accent
  size?: 'sm' | 'md' | 'lg'
  className?: string
}) {
  const sizes = {
    sm: 'h-7 w-7',
    md: 'h-9 w-9',
    lg: 'h-11 w-11',
  } as const

  return (
    <span
      className={clsx(
        'relative flex shrink-0 items-center justify-center rounded-full ring-1 ring-inset',
        sizes[size],
        ACCENT_BG_SOFT[accent],
        ACCENT_TEXT[accent],
        accentRing(accent),
        className,
      )}
    >
      <span aria-hidden className={clsx('absolute inset-0 rounded-full opacity-60 blur-md', ACCENT_BG_SOFT[accent])} />
      <span className="relative flex items-center justify-center">{icon}</span>
    </span>
  )
}

// Literal class strings, JIT-safe (see accent.ts for why).
function accentRing(accent: Accent): string {
  switch (accent) {
    case 'blue':
      return 'ring-accent-blue/30'
    case 'cyan':
      return 'ring-accent-cyan/30'
    case 'violet':
      return 'ring-accent-violet/30'
    case 'green':
      return 'ring-accent-green/30'
    case 'amber':
      return 'ring-accent-amber/30'
    case 'red':
      return 'ring-accent-red/30'
    default:
      return 'ring-white/10'
  }
}
