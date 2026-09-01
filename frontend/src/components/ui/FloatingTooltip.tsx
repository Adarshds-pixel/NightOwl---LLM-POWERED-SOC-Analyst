import clsx from 'clsx'
import { useRef, useState, type ReactNode } from 'react'
import { createPortal } from 'react-dom'

const VIEWPORT_MARGIN = 8
const VERTICAL_GAP = 8
const MAX_WIDTH = 240

interface Position {
  top: number
  left: number
  placement: 'top' | 'bottom'
}

/**
 * A viewport-aware tooltip for triggers packed edge-to-edge inside a
 * horizontally-scrolling container -- the MITRE heatmap's use case, where
 * the plain CSS `Tooltip` (centered, `whitespace-nowrap`, no portal) gets
 * clipped by the scroll container for the first/last columns and by the
 * screen edge for a long technique name.
 *
 * Portals to `document.body` (same precedent as `Modal`/`Drawer` in
 * overlays.tsx) so the scroll container's `overflow-x-auto` can never clip
 * it, computes the trigger's `getBoundingClientRect()` on hover/focus to
 * flip above/below and clamp left/right so the bubble always stays fully
 * on screen, and wraps text (no `whitespace-nowrap`) within a max width so
 * a long name grows downward instead of sideways off the edge.
 *
 * Position is computed once per hover-start, not tracked continuously --
 * this is for a dense grid of small static cells, not a layout that moves
 * while a tooltip is open.
 */
export function FloatingTooltip({ label, children, className }: { label: ReactNode; children: ReactNode; className?: string }) {
  const [position, setPosition] = useState<Position | null>(null)
  const triggerRef = useRef<HTMLSpanElement>(null)

  function show() {
    const rect = triggerRef.current?.getBoundingClientRect()
    if (!rect) return

    const spaceAbove = rect.top
    const placement: Position['placement'] = spaceAbove >= 60 ? 'top' : 'bottom'
    const top = placement === 'top' ? rect.top - VERTICAL_GAP : rect.bottom + VERTICAL_GAP

    const centered = rect.left + rect.width / 2
    const halfWidth = MAX_WIDTH / 2
    const left = Math.min(
      Math.max(centered, halfWidth + VIEWPORT_MARGIN),
      window.innerWidth - halfWidth - VIEWPORT_MARGIN,
    )

    setPosition({ top, left, placement })
  }

  function hide() {
    setPosition(null)
  }

  return (
    <>
      <span
        ref={triggerRef}
        className={clsx('inline-flex', className)}
        onMouseEnter={show}
        onMouseLeave={hide}
        onFocus={show}
        onBlur={hide}
      >
        {children}
      </span>
      {position &&
        createPortal(
          <span
            role="tooltip"
            className="pointer-events-none fixed z-50 rounded-md border border-line-strong bg-surface-2 px-2 py-1 text-micro text-text-dim shadow-elevated"
            style={{
              top: position.top,
              left: position.left,
              maxWidth: MAX_WIDTH,
              transform: `translate(-50%, ${position.placement === 'top' ? '-100%' : '0'})`,
            }}
          >
            {label}
          </span>,
          document.body,
        )}
    </>
  )
}
