import clsx from 'clsx'
import { ACCENT_DOT_CLASSES, ACCENT_TEXT_CLASSES, type Accent } from './accent'

type Tone = 'good' | 'bad' | 'warn' | 'neutral'

const TONE_ACCENT: Record<Tone, Accent> = {
  good: 'green',
  bad: 'red',
  warn: 'amber',
  neutral: 'neutral',
}

export function StatusPill({ tone, label }: { tone: Tone; label: string }) {
  const accent = TONE_ACCENT[tone]
  return (
    <span className="inline-flex items-center gap-2 text-xs font-medium tracking-wide">
      <span className={clsx('h-2 w-2 rounded-full', ACCENT_DOT_CLASSES[accent])} />
      <span className={ACCENT_TEXT_CLASSES[accent]}>{label}</span>
    </span>
  )
}
