import clsx from 'clsx'
import { Crosshair, Network, ShieldAlert } from 'lucide-react'
import { useEffect } from 'react'
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
import {
  activityAnchorMs,
  computeThreatLevel,
  hostActivity,
  selectMostActionableIncident,
  type ThreatLevel,
} from '../lib/aggregations'

/** Visual language per computed threat level -- reuses the same
 *  `computeThreatLevel` the sidebar's status block already shows, just given
 *  the visual weight the brief asks the dashboard's top-of-hierarchy
 *  "threat situation" to carry. Nothing here is a second source of truth. */
const THREAT_STYLES: Record<ThreatLevel, { text: string; border: string; dot: string; glow?: string }> = {
  NOMINAL: { text: 'text-accent-green', border: 'border-line', dot: 'bg-accent-green' },
  LOW: { text: 'text-accent-violet', border: 'border-accent-violet/25', dot: 'bg-accent-violet' },
  MODERATE: { text: 'text-accent-amber', border: 'border-accent-amber/30', dot: 'bg-accent-amber' },
  ELEVATED: {
    text: 'text-accent-orange',
    border: 'border-accent-orange/35',
    dot: 'bg-accent-orange animate-pulse-dot',
    glow: 'shadow-glow-orange',
  },
  CRITICAL: {
    text: 'text-accent-red',
    border: 'border-accent-red/45',
    dot: 'bg-accent-red animate-pulse-dot',
    glow: 'shadow-glow-red',
  },
}

function ThreatBanner({ level, activeCount }: { level: ThreatLevel; activeCount: number }) {
  const style = THREAT_STYLES[level]
  return (
    <div
      className={clsx(
        'flex items-center gap-3 rounded-card border bg-surface-1/60 px-4 py-2.5 backdrop-blur-[var(--blur-glass)] backdrop-saturate-[1.2] transition-colors duration-300',
        style.border,
        style.glow,
      )}
    >
      <span className="relative flex h-2.5 w-2.5 shrink-0">
        <span className={clsx('absolute inset-0 rounded-full opacity-60', style.dot)} />
        <span className={clsx('relative h-2.5 w-2.5 rounded-full', style.dot.split(' ')[0])} />
      </span>
      <ShieldAlert className={clsx('h-4 w-4 shrink-0', style.text)} />
      <p className="text-meta text-text-dim">
        Threat level <span className={clsx('font-semibold tracking-wide', style.text)}>{level}</span>
        <span className="text-text-faint">
          {' '}
          -- {activeCount} active incident{activeCount === 1 ? ' requires' : 's require'} attention
        </span>
      </p>
    </div>
  )
}

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
const DASHBOARD_REFRESH_MS = 30_000

function DashboardPage() {
  const { incidents, meta, loading, error, refresh } = useIncidentsSnapshot()
  const { byId } = useMitreCatalog()
  // Detections only (ML anomaly records are never counted as alerts), and
  // refreshed on the same 30 s cadence as the incident snapshot so the KPI
  // row never mixes fresh incident counts with stale alert counts.
  const alertsQuery = useAlerts({ limit: 200, kind: 'detection' }, DASHBOARD_REFRESH_MS)
  const { eventTotal, alertTotal: alertingEventTotal, refresh: refreshEventTotals } = useEventTotals()
  useEffect(() => {
    const timer = window.setInterval(refreshEventTotals, DASHBOARD_REFRESH_MS)
    return () => window.clearInterval(timer)
  }, [refreshEventTotals])
  // A file uploaded from this page's own empty-state control needs both
  // the incidents snapshot AND the event totals (PipelineHealthPanel's
  // eventTotal below) to catch up -- refresh() alone used to leave
  // eventTotal frozen at whatever it was when this page first mounted.
  // The upload's verdict (telemetry profile, AI review) lives on Logs only.
  function handleUploadSuccess() {
    refresh()
    refreshEventTotals()
  }

  const graph = hostActivity(incidents)
  const focusIncident = selectMostActionableIncident(incidents)
  const threat = computeThreatLevel(incidents)

  // NightOwl ingests historical EVTX archives, not a live feed -- alert and
  // incident timestamps are the real event time from the source log, which
  // can be years before actual wall-clock "now". The recent-activity
  // graphs/deltas below anchor to the most recent timestamp actually in
  // this dataset instead of Date.now(), so they show real data instead of
  // being permanently empty; every series on this page shares the same
  // anchor rather than each computing its own.
  const activityNow = activityAnchorMs(
    incidents.map((incident) => incident.created_at),
    alertsQuery.alerts.map((alert) => alert.timestamp),
  )

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
      <div className="flex flex-col gap-4 p-5">
        <Card>
          <EmptyState
            message="Nothing ingested yet"
            hint="Upload a Windows EVTX export or run Demo Mode, and the whole console fills in from the real detection pipeline."
            action={
              <div className="mt-2">
                <LogUploadControl variant="primary" onSuccess={handleUploadSuccess} />
              </div>
            }
          />
        </Card>
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-4 p-5">
      <ThreatBanner level={threat.level} activeCount={threat.activeCount} />

      <KpiRow incidents={incidents} meta={meta} alerts={alertsQuery.alerts} alertTotal={alertsQuery.total} now={activityNow} />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <div className="xl:col-span-3">
          <SeverityDonutPanel meta={meta} />
        </div>
        <Card
          title="MITRE ATT&CK heatmap"
          subtitle="Observed techniques by tactic"
          icon={<Crosshair className="h-3.5 w-3.5" />}
          accent="magenta"
          action={<ViewAllLink to="/mitre" label="Full matrix" />}
          className="xl:col-span-5"
          bodyClassName="flex flex-col justify-center"
        >
          <HeatmapGrid incidents={incidents} techniqueById={byId} compact maxRows={7} />
        </Card>
        <div className="xl:col-span-4">
          <AiAssistantPanel
            incident={focusIncident}
            investigatingCount={incidents.filter((item) => item.status === 'investigating').length}
          />
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
          accent="magenta"
          className="xl:col-span-3"
          bodyClassName="flex flex-col justify-center"
        >
          <HostGraph nodes={graph.nodes} edges={graph.edges} />
          <HostGraphLegend />
        </Card>
        <div className="xl:col-span-3">
          <PipelineHealthPanel
            alerts={alertsQuery.alerts}
            eventTotal={eventTotal}
            alertTotal={alertingEventTotal}
            now={activityNow}
          />
        </div>
      </div>
    </div>
  )
}

export default DashboardPage
