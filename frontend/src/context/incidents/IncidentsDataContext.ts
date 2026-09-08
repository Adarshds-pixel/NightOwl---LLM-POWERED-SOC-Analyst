import { createContext } from 'react'
import type { IncidentSummary } from '../../api'

export interface IncidentsMeta {
  totalAll: number
  totalCritical: number
  totalHigh: number
  totalMedium: number
  totalLow: number
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
