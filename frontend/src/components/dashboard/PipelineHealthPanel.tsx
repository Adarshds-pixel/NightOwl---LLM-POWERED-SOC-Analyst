import { Activity, Cpu } from 'lucide-react'
import type { EventLogRow } from '../../api'
import { useHealth } from '../../context/health/useHealth'
import { useRules } from '../../hooks/useRules'
import { useSystemStatus } from '../../hooks/useSystemStatus'
import { activityByHour } from '../../lib/events'
import { formatLatency } from '../../lib/format'
import { ACCENT } from '../../lib/tokens'
import { Card, ChartLegend, MiniStat, RingGauge, TrendChart } from '../ui'

/**
 * Pipeline health.
 *
 * The mockup shows CPU / memory / disk / network gauges, which would need
 * host telemetry NightOwl does not collect (there is no psutil dependency
 * and no metrics endpoint -- /health is a liveness probe). Rather than draw
 * four numbers nobody measured, this panel reports the four things the
 * system genuinely knows about itself: whether the API answers and how
 * fast, how many detection rules are loaded, how much telemetry has been
 * ingested, and how much of it tripped a rule.
 */
export function PipelineHealthPanel({
  alerts,
  eventTotal,
  alertTotal,
  now,
}: {
  alerts: EventLogRow[]
  eventTotal: number
  alertTotal: number
  /** Shared recent-activity anchor (epoch ms), computed once by the caller
   *  from the datasets feeding this page -- see lib/aggregations.ts's
   *  `latestTimestampMs`. NightOwl's alert timestamps are the real
   *  historical EVTX event time, not upload time, so anchoring to
   *  `Date.now()` here would leave this chart empty for any real corpus. */
  now: number
}) {
  const { status, latencyMs, samples } = useHealth()
  const { rules } = useRules()
  const { status: system } = useSystemStatus()

  const online = status === 'healthy'
  const components = system
    ? [system.detection_rules, system.llm, system.knowledge_base, system.ml_anomaly_layer]
    : []
  const readyCount = components.filter((component) => component.ready).length
  const detectors = rules.filter((rule) => rule.kind !== 'ml')
  const firedCount = detectors.filter((rule) => rule.match_count > 0).length
  // 400ms is treated as the top of the scale: anything slower than that on
  // a loopback API is already a bad experience, so the ring saturates.
  const latencyScore = latencyMs === null ? 0 : Math.max(0, 100 - Math.min(100, (latencyMs / 400) * 100))
  const detectionRate = eventTotal > 0 ? (alertTotal / eventTotal) * 100 : 0

  const activity = activityByHour(alerts, 12, now)
  const trendData = activity.map((point) => ({ label: point.label, alerts: point.count }))

  return (
    <Card title="Pipeline health" icon={<Cpu className="h-3.5 w-3.5" />} accent="primary">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <RingGauge
          value={online ? latencyScore : 0}
          label="API"
          sublabel={online ? `${formatLatency(latencyMs)} responsiveness` : 'unreachable'}
          accent={online ? 'green' : 'red'}
          unit=""
        />
        <RingGauge
          value={components.length ? (readyCount / components.length) * 100 : 0}
          label="Components"
          sublabel={system ? `${readyCount} of ${components.length} ready` : 'checking'}
          accent="primary"
          unit="%"
        />
        <RingGauge
          value={detectionRate}
          label="Flagged"
          sublabel={`${detectionRate.toFixed(2)}% of ${eventTotal.toLocaleString()} events`}
          accent="violet"
          unit="%"
        />
        <RingGauge
          value={detectors.length ? (firedCount / detectors.length) * 100 : 0}
          label="Fired"
          sublabel={`${firedCount} of ${detectors.length} detectors`}
          accent="magenta"
          unit="%"
        />
      </div>

      <div className="mt-4">
        <div className="mb-1 flex items-center gap-1.5 text-micro tracking-[0.12em] text-text-faint uppercase">
          <Activity className="h-3 w-3" />
          Alerts per hour - most recent 12h of activity
        </div>
        <TrendChart
          data={trendData}
          series={[{ key: 'alerts', label: 'Alerts', color: ACCENT.amber }]}
          height={116}
          area
        />
      </div>

      <div className="mt-3 grid grid-cols-2 gap-2">
        <MiniStat label="API latency" value={formatLatency(latencyMs)} note={`${samples.length} samples this session`} />
        <MiniStat label="Alerting events / events" value={`${alertTotal.toLocaleString()} / ${eventTotal.toLocaleString()}`} note="Events with at least one detection" />
      </div>

      <ChartLegend className="mt-3" series={[{ key: 'alerts', label: 'Rule matches per hour', color: ACCENT.amber }]} />
    </Card>
  )
}
