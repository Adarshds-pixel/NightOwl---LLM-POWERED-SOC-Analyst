import { useEffect, useRef, useState } from 'react'

const DURATION_MS = 700

/**
 * Eased count-up for KPI metrics. `enabled` lets the Settings page turn the
 * animation off (and honours the reduced-motion preference) without every
 * call site branching -- when disabled the target value is returned
 * immediately, no rAF loop is scheduled.
 */
export function useCountUp(target: number, enabled = true): number {
  const [value, setValue] = useState(target)
  const fromRef = useRef(target)
  const rafRef = useRef<number | null>(null)

  useEffect(() => {
    if (!enabled || prefersReducedMotion()) {
      fromRef.current = target
      setValue(target)
      return
    }

    const from = fromRef.current
    const start = performance.now()

    function tick(now: number) {
      const t = Math.min((now - start) / DURATION_MS, 1)
      const eased = 1 - (1 - t) * (1 - t)
      setValue(Math.round(from + (target - from) * eased))
      if (t < 1) rafRef.current = requestAnimationFrame(tick)
      else fromRef.current = target
    }

    rafRef.current = requestAnimationFrame(tick)
    return () => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current)
    }
  }, [target, enabled])

  return value
}

function prefersReducedMotion(): boolean {
  return typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches
}
