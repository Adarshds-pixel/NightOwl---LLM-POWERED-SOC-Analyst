import { useContext } from 'react'
import { IncidentsDataContext } from './IncidentsDataContext'

export function useIncidentsSnapshot() {
  const ctx = useContext(IncidentsDataContext)
  if (!ctx) throw new Error('useIncidentsSnapshot must be used within IncidentsDataProvider')
  return ctx
}
