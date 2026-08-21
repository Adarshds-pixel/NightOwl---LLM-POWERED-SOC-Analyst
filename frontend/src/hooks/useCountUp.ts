import { useEffect, useRef, useState } from 'react'

const DURATION_MS = 700

export function useCountUp(target: number): number {
  const [value, setValue] = useState(target)
  const fromRef = useRef(target)
  const rafRef = useRef<number | null>(null)

  useEffect(() => {
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
  }, [target])

  return value
}
