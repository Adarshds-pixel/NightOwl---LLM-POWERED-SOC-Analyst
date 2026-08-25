import { ActiveAlertsFeed } from '../components/dashboard/ActiveAlertsFeed'
import { AiAssistantPanel } from '../components/dashboard/AiAssistantPanel'
import { AnalyticsRow } from '../components/dashboard/AnalyticsRow'
import { KpiRow } from '../components/dashboard/KpiRow'
import { QuickActionsPanel } from '../components/dashboard/QuickActionsPanel'
import { SystemHealthPanel } from '../components/dashboard/SystemHealthPanel'
import { ThreatMatrixPanel } from '../components/dashboard/ThreatMatrixPanel'
import { EmptyState, ErrorState, LoadingState } from '../components/ui'
import { useIncidentsSnapshot } from '../context/incidents/useIncidentsSnapshot'
import { useMitreCatalog } from '../context/mitre/useMitreCatalog'

function DashboardPage() {
  const { incidents, meta, loading, error, refresh } = useIncidentsSnapshot()
  const { byId } = useMitreCatalog()

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-text">Dashboard</h1>
        <p className="mt-1 text-sm text-text-muted">Real-time incident overview, derived entirely from the live API.</p>
      </div>

      {loading && <LoadingState label="Fetching incidents" />}
      {error && !loading && <ErrorState message={error} onRetry={refresh} />}

      {!loading && !error && incidents.length === 0 && (
        <EmptyState message="No incidents ingested yet -- upload logs or open Demo Mode below to populate the dashboard" />
      )}

      {!loading && !error && incidents.length > 0 && (
        <>
          <KpiRow incidents={incidents} meta={meta} />
          <ActiveAlertsFeed />
          <ThreatMatrixPanel
            incidents={incidents}
            truncated={meta.truncated}
            fetchedCount={meta.fetchedCount}
            totalAll={meta.totalAll}
          />
          <AnalyticsRow incidents={incidents} techniqueById={byId} />
        </>
      )}

      {!loading && !error && (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          <QuickActionsPanel />
          <AiAssistantPanel />
          <SystemHealthPanel />
        </div>
      )}
    </div>
  )
}

export default DashboardPage
