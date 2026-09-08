import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { getMitreTechniques, type MitreTechnique } from '../../api'
import { useAuth } from '../auth/useAuth'
import { MitreCatalogContext } from './MitreCatalogContext'

export function MitreCatalogProvider({ children }: { children: ReactNode }) {
  const { status } = useAuth()
  const [techniques, setTechniques] = useState<MitreTechnique[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    // This provider sits above the router (see AppProviders/main.tsx), so
    // it never unmounts across a /login -> dashboard navigation. Gating
    // the fetch on `status === 'authenticated'` (rather than `[]`, fetch
    // exactly once ever) matters specifically because this provider is
    // also mounted while the admin is still on /login: without this
    // gate, its one-and-only fetch could fire before login completes,
    // get a 401, and then never retry for the rest of the browser
    // session even after a successful sign-in. Re-fires on every
    // login/logout/login cycle, not just the first -- still effectively
    // one real fetch per authenticated session, since the catalog itself
    // (858 entries) never changes.
    if (status !== 'authenticated') return
    let cancelled = false
    getMitreTechniques()
      .then((res) => {
        if (!cancelled) setTechniques(res.techniques)
      })
      .catch((err: Error) => {
        if (!cancelled) setError(err.message)
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [status])

  const byId = useMemo(() => new Map(techniques.map((t) => [t.id, t])), [techniques])
  const byTactic = useMemo(() => {
    const map = new Map<string, MitreTechnique[]>()
    for (const technique of techniques) {
      for (const tactic of technique.tactics) {
        const list = map.get(tactic) ?? []
        list.push(technique)
        map.set(tactic, list)
      }
    }
    return map
  }, [techniques])

  const value = useMemo(
    () => ({ techniques, byId, byTactic, loading, error }),
    [techniques, byId, byTactic, loading, error],
  )

  return <MitreCatalogContext.Provider value={value}>{children}</MitreCatalogContext.Provider>
}
