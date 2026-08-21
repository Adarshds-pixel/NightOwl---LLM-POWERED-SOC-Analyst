import { useContext } from 'react'
import { MitreCatalogContext } from './MitreCatalogContext'

export function useMitreCatalog() {
  const ctx = useContext(MitreCatalogContext)
  if (!ctx) throw new Error('useMitreCatalog must be used within MitreCatalogProvider')
  return ctx
}
