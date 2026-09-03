import clsx from 'clsx'

/**
 * The mirrored sheen beneath a hero surface, as in the login reference.
 *
 * A real CSS effect, not an image.
 *
 * Implementation note: the obvious approach is to render the card's own
 * subtree a second time, flipped on Y. That was rejected -- a duplicated
 * subtree puts a second copy of every input and button in the DOM, and
 * `pointer-events: none` does NOT remove them from the tab order, so the
 * keyboard focus ring would vanish into an invisible mirror copy. It also
 * doubles paint cost on the largest panels.
 *
 * Instead this paints the card's *silhouette*: a rounded, blurred, violet
 * echo that fades out within its own height. Against a glass panel -- which
 * is mostly a soft rounded rectangle of light anyway -- it reads the same,
 * costs one element, and can never touch focus order.
 *
 * Use selectively: hero panels, the login card, major visualisations.
 */
export function Reflection({
  className,
  /** Height of the echo relative to the source card. */
  height = '38%',
  /** Set on a magenta-accented panel so the echo matches its own light. */
  tone = 'violet',
}: {
  className?: string
  height?: string
  tone?: 'violet' | 'magenta'
}) {
  const tint =
    tone === 'magenta'
      ? 'rgba(236, 72, 153, 0.22), rgba(124, 58, 237, 0.10)'
      : 'rgba(139, 92, 246, 0.24), rgba(236, 72, 153, 0.09)'

  return (
    <span
      aria-hidden
      className={clsx('pointer-events-none absolute inset-x-4 top-full block select-none', className)}
      style={{
        height,
        background: `linear-gradient(to bottom, ${tint}, transparent 78%)`,
        borderRadius: '0 0 var(--radius-card) var(--radius-card)',
        filter: 'blur(14px)',
        maskImage: 'linear-gradient(to bottom, rgba(0,0,0,0.8), transparent 82%)',
        WebkitMaskImage: 'linear-gradient(to bottom, rgba(0,0,0,0.8), transparent 82%)',
        transform: 'scaleY(-1)',
      }}
    />
  )
}
