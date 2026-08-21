import type { ReactNode } from 'react'
import { IncidentsDataProvider } from './incidents/IncidentsDataProvider'
import { MitreCatalogProvider } from './mitre/MitreCatalogProvider'

export function AppProviders({ children }: { children: ReactNode }) {
  return (
    <MitreCatalogProvider>
      <IncidentsDataProvider>{children}</IncidentsDataProvider>
    </MitreCatalogProvider>
  )
}
