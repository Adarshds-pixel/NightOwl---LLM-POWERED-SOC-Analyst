import { useEffect, useRef } from 'react'

/**
 * A very soft violet spotlight that follows the pointer.
 *
 * Deliberately understated: the brief asks for something felt rather than
 * seen, so this is ~7% opacity and never draws a hard edge.
 *
 * Performance notes, because a naive version of this is a classic jank
 * source:
 *   - the listener only stores coordinates; the DOM write happens once per
 *     animation frame, so a fast mouse cannot queue up style recalcs
 *   - it writes two CSS custom properties on one element, and the gradient
 *     that consumes them lives in index.css -- React never re-renders
 *   - `pointer: coarse` devices never attach a listener at all (and
 *     `.cursor-glow` is also display:none there as a second guard)
 */
export function CursorGlow() {
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    // Touch/pen devices have no meaningful hover position to track.
    if (typeof window === 'undefined') return
    if (!window.matchMedia('(pointer: fine)').matches) return

    const element = ref.current
    if (!element) return

    let x = window.innerWidth / 2
    let y = window.innerHeight / 2
    let frame = 0

    function onMove(event: MouseEvent) {
      x = event.clientX
      y = event.clientY
      if (frame) return
      frame = window.requestAnimationFrame(() => {
        frame = 0
        element?.style.setProperty('--mouse-x', `${x}px`)
        element?.style.setProperty('--mouse-y', `${y}px`)
      })
    }

    window.addEventListener('mousemove', onMove, { passive: true })
    return () => {
      window.removeEventListener('mousemove', onMove)
      if (frame) window.cancelAnimationFrame(frame)
    }
  }, [])

  return <div ref={ref} className="cursor-glow" aria-hidden />
}
