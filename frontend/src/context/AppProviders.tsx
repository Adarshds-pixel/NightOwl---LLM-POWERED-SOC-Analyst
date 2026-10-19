import type { ReactNode } from 'react'
import { HealthProvider } from './health/HealthProvider'
import { IncidentsDataProvider } from './incidents/IncidentsDataProvider'
import { IngestProvider } from './ingest/IngestProvider'
import { MitreCatalogProvider } from './mitre/MitreCatalogProvider'
import { PreferencesProvider } from './preferences/PreferencesProvider'
import { ToastProvider } from './toast/ToastProvider'

/**
 * Provider order matters: preferences first (the incidents provider reads
 * the refresh interval from it), then the shared caches, then toasts, which
 * anything below may push into. The upload sits innermost: it refreshes the
 * incident snapshot and reports through toasts.
 */
export function AppProviders({ children }: { children: ReactNode }) {
  return (
    <PreferencesProvider>
      <ToastProvider>
        <HealthProvider>
          <MitreCatalogProvider>
            <IncidentsDataProvider>
              <IngestProvider>{children}</IngestProvider>
            </IncidentsDataProvider>
          </MitreCatalogProvider>
        </HealthProvider>
      </ToastProvider>
    </PreferencesProvider>
  )
}
