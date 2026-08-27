import clsx from 'clsx'
import type { ButtonHTMLAttributes, ReactNode } from 'react'
import { Link } from 'react-router-dom'

/**
 * Every button in the app. Before this existed the same ten-utility class
 * string was pasted into six components with only the accent swapped, which
 * is exactly how a design system drifts.
 *
 * variants:
 *   primary   - the one affirmative action on a screen (violet-to-blue fill)
 *   secondary - bordered glass, the default for most actions
 *   ghost     - text-only, for toolbar and row actions
 *   danger    - destructive/critical
 *   icon      - square icon-only control (search, bell, kebab)
 */

type Variant = 'primary' | 'secondary' | 'ghost' | 'danger' | 'icon'
type Size = 'sm' | 'md' | 'lg'

const VARIANTS: Record<Variant, string> = {
  primary:
    'border-accent-violet/40 bg-gradient-to-r from-accent-violet/90 to-accent-blue/80 text-white shadow-glow-violet hover:from-accent-violet hover:to-accent-blue',
  secondary: 'border-line-strong bg-surface-2/70 text-text-dim hover:border-accent-blue/40 hover:text-text',
  ghost: 'border-transparent bg-transparent text-text-muted hover:bg-white/5 hover:text-text',
  danger: 'border-accent-red/40 bg-accent-red/12 text-accent-red hover:bg-accent-red/20',
  icon: 'border-line bg-surface-2/60 text-text-dim hover:border-accent-blue/40 hover:text-text',
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

const BASE =
  'inline-flex shrink-0 items-center justify-center rounded-control border font-semibold tracking-wide transition-colors duration-200 disabled:cursor-not-allowed disabled:opacity-45'

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
