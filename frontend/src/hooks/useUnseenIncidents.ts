import { useCallback, useMemo, useState } from 'react'
import type { IncidentSummary } from '../api'

const STORAGE_KEY = 'nightowl:seen-incident-ids'

// Client-side-only "seen" tracking -- the backend has no per-user read-state
// concept, so this is honestly scoped as per-browser, not a synced/
// authoritative read receipt. Wrapped in try/catch since localStorage can
// throw (private browsing, storage disabled).
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
    // Storage unavailable -- badge just won't persist across reloads.
  }
}

export function useUnseenIncidents(incidents: IncidentSummary[]) {
  const [seenIds, setSeenIds] = useState<Set<number>>(loadSeenIds)

  const unseenCount = useMemo(
    () => incidents.filter((i) => i.status === 'open' && !seenIds.has(i.id)).length,
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

  return { unseenCount, markAllSeen }
}
