import clsx from 'clsx'
import { ACCENT_BORDER_SOFT_CLASSES, ACCENT_TEXT_CLASSES, type Accent } from './accent'

interface MiniStatProps {
  label: string
  value: number | string
  accent?: Accent
  note?: string
}

export function MiniStat({ label, value, accent = 'cyan', note }: MiniStatProps) {
  return (
    <div className={clsx('rounded border bg-surface/40 px-3 py-2', ACCENT_BORDER_SOFT_CLASSES[accent])}>
      <div className="text-[10px] tracking-widest text-text-muted uppercase">{label}</div>
      <div className={clsx('text-xl font-bold tabular-nums', ACCENT_TEXT_CLASSES[accent])}>{value}</div>
      {note && <div className="text-[10px] text-text-muted">{note}</div>}
    </div>
  )
}
