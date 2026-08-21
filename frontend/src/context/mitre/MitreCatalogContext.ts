import { createContext } from 'react'
import type { MitreTechnique } from '../../api'

export interface MitreCatalog {
  techniques: MitreTechnique[]
  byId: Map<string, MitreTechnique>
  byTactic: Map<string, MitreTechnique[]>
  loading: boolean
  error: string | null
}

export const MitreCatalogContext = createContext<MitreCatalog | null>(null)
