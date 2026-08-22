import type { ReactNode } from 'react'

export function EmptyState({ message, icon }: { message: string; icon?: ReactNode }) {
  return (
    <div className="flex flex-col items-center gap-2 py-8 text-center text-text-muted">
      {icon}
      <span className="text-xs tracking-widest uppercase">{message}</span>
    </div>
  )
}
