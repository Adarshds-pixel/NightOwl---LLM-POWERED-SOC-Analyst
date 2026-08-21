import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { getMitreTechniques, type MitreTechnique } from '../../api'
import { MitreCatalogContext } from './MitreCatalogContext'

export function MitreCatalogProvider({ children }: { children: ReactNode }) {
  const [techniques, setTechniques] = useState<MitreTechnique[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
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
    // Fetched exactly once per session -- this is static reference data
    // (858 entries), never refetched on navigation.
  }, [])

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
