import { ACCENT_BORDER_CLASSES, type Accent } from './accent'

export function HudCorners({ accent = 'cyan' }: { accent?: Accent }) {
  const cls = ACCENT_BORDER_CLASSES[accent]
  return (
    <span aria-hidden className="pointer-events-none absolute inset-0">
      <span className={`absolute -top-px -left-px h-3 w-3 border-t-2 border-l-2 ${cls}`} />
      <span className={`absolute -top-px -right-px h-3 w-3 border-t-2 border-r-2 ${cls}`} />
      <span className={`absolute -bottom-px -left-px h-3 w-3 border-b-2 border-l-2 ${cls}`} />
      <span className={`absolute -bottom-px -right-px h-3 w-3 border-b-2 border-r-2 ${cls}`} />
    </span>
  )
}
