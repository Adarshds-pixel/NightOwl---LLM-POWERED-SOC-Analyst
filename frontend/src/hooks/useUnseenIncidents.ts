import { useCallback, useMemo, useState } from 'react'
import type { IncidentSummary } from '../api'

const STORAGE_KEY = 'nightowl:seen-incident-ids'

// Client-side-only "seen" tracking -- the backend has no per-user read
// state, so this is honestly scoped as per-browser, not a synced read
// receipt. Wrapped in try/catch since localStorage can throw (private
// browsing, storage disabled).
function loadSeenIds(): Set<number> {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    return raw ? new Set(JSON.parse(raw)) : new Set()
  } catch {
    return new Set()
  }
}

function saveSeenIds(ids: Set<number>) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify([...ids]))
  } catch {
    // Storage unavailable -- the badge just will not persist across reloads.
  }
}

/**
 * Backs the notification bell. A "notification" here is a real open
 * incident this browser has not acknowledged yet -- NightOwl has no
 * notifications table, and inventing one would mean inventing its contents
 * too. The panel therefore shows exactly what it can prove: new open
 * incidents, newest first.
 */
export function useUnseenIncidents(incidents: IncidentSummary[]) {
  const [seenIds, setSeenIds] = useState<Set<number>>(loadSeenIds)

  const unseen = useMemo(
    () =>
      incidents
        .filter((incident) => incident.status === 'open' && !seenIds.has(incident.id))
        .sort((a, b) => b.created_at.localeCompare(a.created_at)),
    [incidents, seenIds],
  )

  const markAllSeen = useCallback(() => {
    setSeenIds((prev) => {
      const next = new Set(prev)
      for (const incident of incidents) next.add(incident.id)
      saveSeenIds(next)
      return next
    })
  }, [incidents])

  const markSeen = useCallback((id: number) => {
    setSeenIds((prev) => {
      const next = new Set(prev)
      next.add(id)
      saveSeenIds(next)
      return next
    })
  }, [])

  return { unseen, unseenCount: unseen.length, markAllSeen, markSeen }
}
