import { isRateLimited } from '../api'

/**
 * Shared rules for every background poller in the app (health, live log
 * stream, incident snapshot).
 *
 * Two behaviours, both learned from the backend rate limiter: a hidden tab
 * has no reason to spend request budget at all, and a poller that keeps
 * hammering a throttled API is what stops the token bucket from ever
 * refilling enough for the visible page to load. Backing off hands the
 * recovering capacity to the requests the analyst is actually waiting on.
 */

export function isDocumentVisible(): boolean {
  return typeof document === 'undefined' || document.visibilityState === 'visible'
}

/** Multiplier applied to a poll interval after `failures` consecutive 429s,
 *  capped so a poller never goes completely silent. */
export function backoffMultiplier(failures: number): number {
  if (failures <= 0) return 1
  return Math.min(2 ** failures, 8)
}

/** Whether this tick should be skipped: either the tab is hidden, or we are
 *  still inside the backoff window after being throttled. */
export function shouldSkipPoll(failures: number, ticksSinceLastAttempt: number): boolean {
  if (!isDocumentVisible()) return true
  return ticksSinceLastAttempt < backoffMultiplier(failures)
}

export function countFailure(error: unknown, current: number): number {
  // Only throttling backs the poller off. A genuine outage should keep
  // retrying at the normal cadence so the UI notices the moment it returns.
  return isRateLimited(error) ? current + 1 : 0
}
