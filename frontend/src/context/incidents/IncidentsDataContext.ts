import { createContext } from 'react'
import type { IncidentSummary } from '../../api'

export interface IncidentsMeta {
  totalAll: number
  totalCritical: number
  totalHigh: number
  totalMedium: number
  totalLow: number
  /** Whatever the four bands above leave out of totalAll. No current rule
   *  produces an informational incident, so this is 0 today; it exists so
   *  the bands can never silently add up to less than the total. */
  totalInformational: number
  totalOpen: number
  totalInvestigating: number
  fetchedCount: number
  truncated: boolean
}

export interface IncidentsSnapshot {
  incidents: IncidentSummary[]
  meta: IncidentsMeta
  loading: boolean
  error: string | null
  refresh: () => void
}

export const IncidentsDataContext = createContext<IncidentsSnapshot | null>(null)
