import { Crosshair, Network } from 'lucide-react'
import { ActiveIncidentsPanel } from '../components/dashboard/ActiveIncidentsPanel'
import { AiAssistantPanel } from '../components/dashboard/AiAssistantPanel'
import { AttackVectorPanel } from '../components/dashboard/AttackVectorPanel'
import { HostGraph, HostGraphLegend } from '../components/dashboard/HostGraph'
import { KpiRow } from '../components/dashboard/KpiRow'
import { LiveLogStreamPanel } from '../components/dashboard/LiveLogStreamPanel'
import { PipelineHealthPanel } from '../components/dashboard/PipelineHealthPanel'
import { RecentAlertsPanel } from '../components/dashboard/RecentAlertsPanel'
import { SeverityDonutPanel } from '../components/dashboard/SeverityDonutPanel'
import { LogUploadControl } from '../components/ingest/LogUploadControl'
import { HeatmapGrid } from '../components/mitre/HeatmapGrid'
import { Card, EmptyState, ErrorState, SkeletonCard, ViewAllLink } from '../components/ui'
import { useIncidentsSnapshot } from '../context/incidents/useIncidentsSnapshot'
import { useMitreCatalog } from '../context/mitre/useMitreCatalog'
import { useAlerts } from '../hooks/useAlerts'
import { useEventTotals } from '../hooks/useEventTotals'
import { hostActivity, selectMostActionableIncident } from '../lib/aggregations'

/**
 * The Overview. Layout mirrors the reference mockup, minus its world
 * threat map: NightOwl ingests local Windows event logs and has no
 * geolocation data of any kind, so that slot is given to the host-activity
 * graph -- the real internal relationship this data supports.
 *
 * Alerts are fetched once here (200 newest) and shared by the KPI row, the
 * recent-alerts list and the pipeline panel, so one page load means one
 * alert query rather than three.
 */
function DashboardPage() {
  const { incidents, meta, loading, error, refresh } = useIncidentsSnapshot()
  const { byId } = useMitreCatalog()
  const alertsQuery = useAlerts({ limit: 200 })
  const { eventTotal } = useEventTotals()

  const graph = hostActivity(incidents)
  const focusIncident = selectMostActionableIncident(incidents)

  if (loading) {
    return (
      <div className="grid grid-cols-1 gap-4 p-5 sm:grid-cols-2 xl:grid-cols-4">
        {Array.from({ length: 8 }).map((_, i) => (
          <SkeletonCard key={i} className={i > 3 ? 'h-64 sm:col-span-2' : ''} />
        ))}
      </div>
    )
  }

  if (error) {
    return <ErrorState className="py-24" message={error} onRetry={refresh} />
  }

  if (incidents.length === 0) {
    return (
      <div className="p-5">
        <Card>
          <EmptyState
            message="Nothing ingested yet"
            hint="Upload a Windows EVTX export or run Demo Mode, and the whole console fills in from the real detection pipeline."
            action={
              <div className="mt-2">
                <LogUploadControl variant="primary" onSuccess={refresh} />
              </div>
            }
          />
        </Card>
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-4 p-5">
      <KpiRow incidents={incidents} meta={meta} alerts={alertsQuery.alerts} alertTotal={alertsQuery.total} />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <div className="xl:col-span-3">
          <SeverityDonutPanel incidents={incidents} />
        </div>
        <Card
          title="MITRE ATT&CK heatmap"
          subtitle="Observed techniques by tactic"
          icon={<Crosshair className="h-3.5 w-3.5" />}
          accent="cyan"
          action={<ViewAllLink to="/mitre" label="Full matrix" />}
          className="xl:col-span-5"
        >
          <HeatmapGrid incidents={incidents} techniqueById={byId} compact maxRows={7} />
        </Card>
        <div className="xl:col-span-4">
          <AiAssistantPanel incident={focusIncident} />
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <div className="xl:col-span-3">
          <AttackVectorPanel incidents={incidents} techniqueById={byId} />
        </div>
        <div className="xl:col-span-5">
          <RecentAlertsPanel
            alerts={alertsQuery.alerts}
            loading={alertsQuery.loading}
            error={alertsQuery.error}
            onRetry={alertsQuery.refresh}
          />
        </div>
        <div className="xl:col-span-4">
          <ActiveIncidentsPanel incidents={incidents} />
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <div className="xl:col-span-6">
          <LiveLogStreamPanel />
        </div>
        <Card
          title="Host activity"
          subtitle="Hosts linked by shared techniques"
          icon={<Network className="h-3.5 w-3.5" />}
          accent="cyan"
          className="xl:col-span-3"
        >
          <HostGraph nodes={graph.nodes} edges={graph.edges} />
          <HostGraphLegend />
        </Card>
        <div className="xl:col-span-3">
          <PipelineHealthPanel alerts={alertsQuery.alerts} eventTotal={eventTotal} alertTotal={alertsQuery.total} />
        </div>
      </div>
    </div>
  )
}

export default DashboardPage
