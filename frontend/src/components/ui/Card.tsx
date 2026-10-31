import clsx from 'clsx'
import type { ReactNode } from 'react'
import { ACCENT_BG_SOFT, ACCENT_BORDER, ACCENT_CARD_SHADOW, ACCENT_GRADIENT, ACCENT_TEXT, type Accent } from './accent'
import { Reflection } from './Reflection'

/**
 * The surface every panel in NightOwl is built on: layered glass with a
 * blurred, saturated backdrop, a hairline border, an internal top-left
 * highlight and an ambient shadow.
 *
 * The highlight is what makes it read as *lit glass* rather than a flat
 * translucent rectangle -- it is a separate absolutely-positioned span
 * rather than a `::before`, because Tailwind cannot express a gradient
 * pseudo-element without arbitrary-property soup, and a real element is
 * easier to reason about when a card also carries a reflection.
 *
 * `accent` tints the title, the optional icon chip, and the card's own
 * border/glow -- a KPI, an AI/RAG surface or a live feed reads as belonging
 * to its channel. Defaults to `neutral` so tables and bare content cards
 * stay plain glass.
 *
 * `hero` raises the card a step in the depth scale and turns on a
 * reflection; reserve it for the one dominant panel on a page (the brief is
 * explicit that reflections on every small card read as a gimmick).
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
  /** Dominant panel on the page: deeper elevation + a floor reflection. */
  hero?: boolean
  /** Lift + brighten on hover. Set for cards that are themselves clickable
   *  or that contain a primary interaction. */
  interactive?: boolean
  className?: string
  bodyClassName?: string
  children?: ReactNode
}

export function Card({
  title,
  subtitle,
  icon,
  accent = 'neutral',
  action,
  divided = false,
  flush = false,
  hero = false,
  interactive = false,
  className,
  bodyClassName,
  children,
}: CardProps) {
  return (
    <section
      className={clsx(
        'relative flex min-w-0 flex-col rounded-card border bg-surface-1/70 bg-gradient-to-b to-transparent',
        'backdrop-blur-[var(--blur-glass)] backdrop-saturate-[1.2]',
        'transition-[transform,box-shadow,border-color] duration-200',
        ACCENT_GRADIENT[accent],
        ACCENT_BORDER[accent],
        hero ? 'shadow-e4' : ACCENT_CARD_SHADOW[accent],
        interactive && 'hover:-translate-y-0.5 hover:border-border-active hover:shadow-card-hover',
        className,
      )}
    >
      {/* Internal specular highlight: light entering from the top-left. */}
      <span
        aria-hidden
        className="pointer-events-none absolute inset-0 rounded-card bg-[linear-gradient(135deg,rgba(255,255,255,0.05),transparent_38%)]"
      />

      {hero && <Reflection tone={accent === 'magenta' ? 'magenta' : 'violet'} />}

      {(title || action) && (
        <header
          className={clsx(
            'relative flex shrink-0 items-start justify-between gap-3 px-4 pt-3.5',
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
      <div className={clsx('relative min-w-0 flex-1', flush ? '' : 'px-4 pt-1 pb-4', bodyClassName)}>{children}</div>
    </section>
  )
}

/**
 * Circular glowing icon container -- the mockups' KPI/statistic marker.
 * Sized in three steps so a KPI card, a card header and a list row can all
 * use the same component without ad-hoc sizing at the call site.
 *
 * Brightens with its parent card on hover via the `group` set by StatCard.
 */
export function IconChip({
  icon,
  accent = 'primary',
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
        'relative flex shrink-0 items-center justify-center rounded-full ring-1 ring-inset transition-all duration-200',
        sizes[size],
        ACCENT_BG_SOFT[accent],
        ACCENT_TEXT[accent],
        accentRing(accent),
        'group-hover:brightness-125',
        className,
      )}
    >
      <span
        aria-hidden
        className={clsx(
          'absolute inset-0 rounded-full opacity-60 blur-md transition-opacity duration-200 group-hover:opacity-100',
          ACCENT_BG_SOFT[accent],
        )}
      />
      <span className="relative flex items-center justify-center">{icon}</span>
    </span>
  )
}

// Literal class strings, JIT-safe (see accent.ts for why).
function accentRing(accent: Accent): string {
  switch (accent) {
    case 'primary':
      return 'ring-accent-primary/30'
    case 'magenta':
      return 'ring-accent-magenta/30'
    case 'violet':
      return 'ring-accent-violet/30'
    case 'green':
      return 'ring-accent-green/30'
    case 'amber':
      return 'ring-accent-amber/30'
    case 'orange':
      return 'ring-accent-orange/30'
    case 'red':
      return 'ring-accent-red/30'
    default:
      return 'ring-line'
  }
}
