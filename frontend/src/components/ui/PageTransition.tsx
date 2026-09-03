import { motion, useReducedMotion } from 'motion/react'
import type { ReactNode } from 'react'
import { usePreferences } from '../../context/preferences/usePreferences'

/**
 * The entrance every route plays: a short fade with a 6px rise.
 *
 * Kept deliberately small (the brief asks for subtle, not dramatic) and
 * short enough that navigation never feels delayed.
 *
 * Two independent opt-outs are honoured: the OS `prefers-reduced-motion`
 * setting via motion's own hook, and NightOwl's in-app "Reduce motion"
 * preference -- a user who set the app switch expects it to win even if
 * their OS says nothing.
 *
 * Uses `motion/react`, already the animation library in overlays.tsx and
 * ToastViewport.tsx, rather than introducing a second approach.
 */
export function PageTransition({ children, routeKey }: { children: ReactNode; routeKey: string }) {
  const systemReduced = useReducedMotion()
  const { prefs } = usePreferences()
  const still = systemReduced || prefs.reduceMotion

  if (still) return <>{children}</>

  return (
    <motion.div
      key={routeKey}
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.26, ease: [0.22, 0.61, 0.36, 1] }}
    >
      {children}
    </motion.div>
  )
}
