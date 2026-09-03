import clsx from 'clsx'
import { motion } from 'motion/react'
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
      {/* Positioning lives on this outer span (a plain translate, computed
          once per hover-start); the inner motion.span only owns the
          fade/scale entrance, so the two concerns never fight over
          `transform`. */}
      {position &&
        createPortal(
          <span
            role="tooltip"
            className="pointer-events-none fixed z-50"
            style={{
              top: position.top,
              left: position.left,
              maxWidth: MAX_WIDTH,
              transform: `translate(-50%, ${position.placement === 'top' ? '-100%' : '0'})`,
            }}
          >
            <motion.span
              initial={{ opacity: 0, scale: 0.92, y: position.placement === 'top' ? 4 : -4 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              transition={{ duration: 0.14, ease: [0.22, 0.61, 0.36, 1] }}
              className="block rounded-control border border-border-active/60 bg-surface-1/95 px-2.5 py-1.5 text-micro text-text-dim shadow-e3 backdrop-blur-[var(--blur-glass)] backdrop-saturate-[1.2]"
            >
              {label}
            </motion.span>
          </span>,
          document.body,
        )}
    </>
  )
}
