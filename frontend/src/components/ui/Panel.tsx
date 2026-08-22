import clsx from 'clsx'
import type { ReactNode } from 'react'
import { ACCENT_BORDER_SOFT_CLASSES, ACCENT_GLOW_CLASSES, ACCENT_TEXT_CLASSES, type Accent } from './accent'
import { HudCorners } from './HudCorners'

interface PanelProps {
  title?: string
  icon?: ReactNode
  accent?: Accent
  action?: ReactNode
  className?: string
  children: ReactNode
}

export function Panel({ title, icon, accent = 'cyan', action, className, children }: PanelProps) {
  return (
    <section
      className={clsx(
        'relative rounded-md border bg-surface/60 p-4 backdrop-blur-sm',
        ACCENT_BORDER_SOFT_CLASSES[accent],
        ACCENT_GLOW_CLASSES[accent],
        className,
      )}
    >
      <HudCorners accent={accent} />
      {title && (
        <header className="mb-3 flex items-center justify-between gap-3">
          <h3
            className={clsx(
              'flex items-center gap-2 text-xs font-semibold tracking-widest uppercase',
              ACCENT_TEXT_CLASSES[accent],
            )}
          >
            {icon}
            {title}
          </h3>
          {action}
        </header>
      )}
      {children}
    </section>
  )
}
