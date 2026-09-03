import clsx from 'clsx'
import { ChevronRight } from 'lucide-react'
import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'

/**
 * In-page header used by every route below the global top bar: page title,
 * optional breadcrumb trail and a right-hand action slot. The top bar shows
 * the same title, so this is only rendered where a page needs breadcrumbs
 * or page-level actions (detail views, generators).
 */
export function PageHeader({
  title,
  subtitle,
  icon,
  breadcrumbs,
  actions,
  className,
}: {
  title: ReactNode
  subtitle?: ReactNode
  icon?: ReactNode
  breadcrumbs?: { label: string; to?: string }[]
  actions?: ReactNode
  className?: string
}) {
  return (
    <header className={clsx('flex flex-wrap items-start justify-between gap-4', className)}>
      <div className="min-w-0">
        <div className="flex items-center gap-2.5">
          {icon}
          <h1 className="truncate text-page font-semibold tracking-tight text-text">{title}</h1>
        </div>
        {breadcrumbs && breadcrumbs.length > 0 && (
          <nav aria-label="Breadcrumb" className="mt-1 flex items-center gap-1 text-meta text-text-muted">
            {breadcrumbs.map((crumb, i) => (
              <span key={crumb.label} className="flex items-center gap-1">
                {i > 0 && <ChevronRight className="h-3 w-3 text-text-faint" />}
                {crumb.to ? (
                  <Link to={crumb.to} className="transition-colors hover:text-accent-primary">
                    {crumb.label}
                  </Link>
                ) : (
                  <span className="text-text-dim">{crumb.label}</span>
                )}
              </span>
            ))}
          </nav>
        )}
        {subtitle && <p className="mt-1 text-meta text-text-muted">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </header>
  )
}
