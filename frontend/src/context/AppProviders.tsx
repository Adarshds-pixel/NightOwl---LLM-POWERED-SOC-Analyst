import type { ReactNode } from 'react'
import { HealthProvider } from './health/HealthProvider'
import { IncidentsDataProvider } from './incidents/IncidentsDataProvider'
import { MitreCatalogProvider } from './mitre/MitreCatalogProvider'
import { PreferencesProvider } from './preferences/PreferencesProvider'
import { ReplayProvider } from './replay/ReplayProvider'
import { ToastProvider } from './toast/ToastProvider'

/**
 * Provider order matters: preferences first (the incidents provider reads
 * the refresh interval from it), then the shared caches, then toasts, which
 * anything below may push into. ReplayProvider sits inside
 * IncidentsDataProvider because it calls that context's refresh() as
 * incidents form during a replay.
 */
export function AppProviders({ children }: { children: ReactNode }) {
  return (
    <PreferencesProvider>
      <ToastProvider>
        <HealthProvider>
          <MitreCatalogProvider>
            <IncidentsDataProvider>
              <ReplayProvider>{children}</ReplayProvider>
            </IncidentsDataProvider>
          </MitreCatalogProvider>
        </HealthProvider>
      </ToastProvider>
    </PreferencesProvider>
  )
}
