import clsx from 'clsx'
import type { ButtonHTMLAttributes, ReactNode } from 'react'
import { Link } from 'react-router-dom'

/**
 * Every button in the app. Before this existed the same ten-utility class
 * string was pasted into six components with only the accent swapped, which
 * is exactly how a design system drifts.
 *
 * variants:
 *   primary   - the one affirmative action on a screen (violet-to-magenta fill)
 *   secondary - bordered glass, the default for most actions
 *   ghost     - text-only, for toolbar and row actions
 *   danger    - destructive/critical
 *   icon      - square icon-only control (search, bell, kebab)
 *
 * Hover adds a 1px lift and a deeper glow rather than a colour swap, so the
 * control feels physical without the layout reflowing under the cursor.
 */

type Variant = 'primary' | 'secondary' | 'ghost' | 'danger' | 'icon'
type Size = 'sm' | 'md' | 'lg'

const VARIANTS: Record<Variant, string> = {
  primary:
    // The inset white hairline is the "internal highlight" that stops the
    // gradient reading as flat printed colour.
    'border-accent-violet/40 bg-gradient-to-br from-accent-violet-deep to-accent-magenta text-white shadow-[inset_0_1px_0_rgba(255,255,255,0.22),0_0_18px_-6px_var(--color-accent-violet)] hover:-translate-y-px hover:from-accent-violet hover:to-accent-pink hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.28),0_0_26px_-6px_var(--color-accent-magenta)]',
  secondary:
    'border-line-strong bg-surface-2/70 text-text-dim backdrop-blur-md hover:-translate-y-px hover:border-accent-primary/50 hover:bg-surface-3/60 hover:text-text hover:shadow-glow-primary',
  ghost: 'border-transparent bg-transparent text-text-muted hover:bg-accent-primary/10 hover:text-text',
  danger:
    'border-accent-red/40 bg-gradient-to-br from-accent-red/25 to-accent-red/10 text-accent-red hover:-translate-y-px hover:from-accent-red/40 hover:to-accent-red/20 hover:text-text hover:shadow-glow-red',
  icon: 'border-line bg-surface-2/60 text-text-dim backdrop-blur-md hover:border-accent-primary/50 hover:text-text hover:shadow-glow-primary',
}

const SIZES: Record<Size, string> = {
  sm: 'h-7 gap-1.5 px-2.5 text-micro',
  md: 'h-9 gap-2 px-3.5 text-meta',
  lg: 'h-11 gap-2 px-5 text-label',
}

const ICON_SIZES: Record<Size, string> = {
  sm: 'h-7 w-7',
  md: 'h-9 w-9',
  lg: 'h-11 w-11',
}

// `active:scale-[.98]` is what makes a button feel physical -- it is the
// press half of the hover lift. Disabled buttons opt out of both.
const BASE =
  'inline-flex shrink-0 items-center justify-center rounded-control border font-semibold tracking-wide transition-all duration-200 active:scale-[.98] disabled:cursor-not-allowed disabled:opacity-45 disabled:hover:translate-y-0 disabled:hover:shadow-none disabled:active:scale-100'

export function buttonClass(variant: Variant = 'secondary', size: Size = 'md', className?: string): string {
  return clsx(BASE, VARIANTS[variant], variant === 'icon' ? ICON_SIZES[size] : SIZES[size], className)
}

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant
  size?: Size
  icon?: ReactNode
  children?: ReactNode
}

export function Button({ variant = 'secondary', size = 'md', icon, children, className, ...rest }: ButtonProps) {
  return (
    <button type="button" className={buttonClass(variant, size, className)} {...rest}>
      {icon}
      {children}
    </button>
  )
}

/** Router link wearing the same clothes as Button -- used for card actions
 *  like "View all" that navigate rather than act. */
export function ButtonLink({
  to,
  variant = 'ghost',
  size = 'sm',
  icon,
  children,
  className,
}: {
  to: string
  variant?: Variant
  size?: Size
  icon?: ReactNode
  children?: ReactNode
  className?: string
}) {
  return (
    <Link to={to} className={buttonClass(variant, size, className)}>
      {children}
      {icon}
    </Link>
  )
}
