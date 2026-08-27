import clsx from 'clsx'
import type { ReactNode } from 'react'

/**
 * Underlined tab bar (MITRE page, incident detail). Rendered as real
 * buttons with the ARIA tab roles so arrow-key navigation and screen
 * readers behave; panels are rendered by the caller.
 */
export interface TabItem<T extends string> {
  value: T
  label: string
  icon?: ReactNode
  count?: number
}

export function Tabs<T extends string>({
  items,
  value,
  onChange,
  className,
}: {
  items: TabItem<T>[]
  value: T
  onChange: (value: T) => void
  className?: string
}) {
  function onKeyDown(event: React.KeyboardEvent<HTMLDivElement>) {
    const index = items.findIndex((item) => item.value === value)
    if (event.key === 'ArrowRight') onChange(items[(index + 1) % items.length].value)
    if (event.key === 'ArrowLeft') onChange(items[(index - 1 + items.length) % items.length].value)
  }

  return (
    <div role="tablist" onKeyDown={onKeyDown} className={clsx('flex items-center gap-1 border-b border-line', className)}>
      {items.map((item) => {
        const active = item.value === value
        return (
          <button
            key={item.value}
            role="tab"
            type="button"
            aria-selected={active}
            tabIndex={active ? 0 : -1}
            onClick={() => onChange(item.value)}
            className={clsx(
              'relative flex items-center gap-1.5 px-3 py-2.5 text-meta font-semibold tracking-[0.08em] uppercase transition-colors duration-200',
              active ? 'text-text' : 'text-text-muted hover:text-text-dim',
            )}
          >
            {item.icon}
            {item.label}
            {item.count !== undefined && (
              <span className="rounded bg-white/6 px-1.5 py-0.5 font-mono text-micro text-text-dim tabular-nums">
                {item.count}
              </span>
            )}
            {active && <span className="absolute inset-x-2 -bottom-px h-0.5 rounded-full bg-accent-blue shadow-glow-blue" />}
          </button>
        )
      })}
    </div>
  )
}
