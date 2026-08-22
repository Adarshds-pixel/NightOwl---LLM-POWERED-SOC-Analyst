import { useIncidentsSnapshot } from '../context/incidents/useIncidentsSnapshot'
import { computeThreatLevel, type ThreatLevel } from '../lib/aggregations'
import { SEVERITY_ORDER } from '../lib/severity'
import { EmptyState, ErrorState, KpiCard, LoadingState, Panel, RingGauge, SeverityBadge, StatusPill } from '../components/ui'
import type { Accent } from '../components/ui'

// RingGauge takes a plain 0-100 fill; ThreatLevel is a discrete category
// (see lib/aggregations.ts), so mapping it to a fill amount is a display
// concern that belongs here, not in the aggregation layer itself.
const THREAT_LEVEL_FILL: Record<ThreatLevel, number> = {
  NOMINAL: 15,
  LOW: 30,
  MODERATE: 55,
  ELEVATED: 80,
  CRITICAL: 100,
}

const THREAT_LEVEL_ACCENT: Record<ThreatLevel, Accent> = {
  NOMINAL: 'green',
  LOW: 'green',
  MODERATE: 'amber',
  ELEVATED: 'red',
  CRITICAL: 'red',
}

function DashboardPage() {
  const { incidents, meta, loading, error, refresh } = useIncidentsSnapshot()
  const threat = computeThreatLevel(incidents)

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-text">Dashboard</h1>
        <p className="mt-1 text-sm text-text-muted">
          Day 15 preview -- shared UI primitives proven against real incident data. Full composition (KPI row
          layout, host-activity graph, live topbar/sidebar) lands Day 16.
        </p>
      </div>

      {loading && <LoadingState label="Fetching incidents" />}
      {error && !loading && <ErrorState message={error} onRetry={refresh} />}

      {!loading && !error && (
        <>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <KpiCard label="Total Incidents" value={meta.totalAll} accent="cyan" />
            <KpiCard label="Critical Threats" value={meta.totalCritical} accent="red" />
            <KpiCard label="Active Incidents" value={meta.totalOpen + meta.totalInvestigating} accent="amber" />
          </div>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <Panel title="Threat Level" accent={THREAT_LEVEL_ACCENT[threat.level]}>
              <div className="flex items-center justify-center py-2">
                <RingGauge
                  value={THREAT_LEVEL_FILL[threat.level]}
                  label={threat.level}
                  sublabel={`${threat.activeCount} active incident${threat.activeCount === 1 ? '' : 's'}`}
                  accent={THREAT_LEVEL_ACCENT[threat.level]}
                />
              </div>
            </Panel>

            <Panel title="Severity Legend" accent="purple" className="lg:col-span-2">
              {incidents.length === 0 ? (
                <EmptyState message="No incidents ingested yet" />
              ) : (
                <div className="flex flex-wrap items-center gap-3">
                  {SEVERITY_ORDER.map((severity) => (
                    <SeverityBadge key={severity} severity={severity} />
                  ))}
                  <span className="ml-auto">
                    <StatusPill tone={meta.truncated ? 'warn' : 'good'} label={`${meta.fetchedCount} of ${meta.totalAll} loaded`} />
                  </span>
                </div>
              )}
            </Panel>
          </div>
        </>
      )}
    </div>
  )
}

export default DashboardPage
