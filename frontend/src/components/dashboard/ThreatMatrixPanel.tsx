import type { IncidentSummary } from '../../api'
import { hostActivity } from '../../lib/aggregations'
import { DETECTION_RULE_COUNT } from '../../lib/constants'
import { MiniStat, Panel, StatusPill } from '../ui'
import { HostGraph } from './HostGraph'

interface ThreatMatrixPanelProps {
  incidents: IncidentSummary[]
  truncated: boolean
  fetchedCount: number
  totalAll: number
}

export function ThreatMatrixPanel({ incidents, truncated, fetchedCount, totalAll }: ThreatMatrixPanelProps) {
  const { nodes, edges } = hostActivity(incidents)

  return (
    <Panel
      title="Threat Matrix"
      accent="cyan"
      action={
        truncated ? (
          <StatusPill tone="warn" label={`Showing ${fetchedCount} of ${totalAll}`} />
        ) : undefined
      }
    >
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[2fr_1fr]">
        <HostGraph nodes={nodes} edges={edges} />
        <div className="flex flex-col gap-2 lg:justify-center">
          <MiniStat label="Active Rules" value={DETECTION_RULE_COUNT} accent="cyan" note="static, sigma rule set" />
          <MiniStat label="Hosts Monitored" value={nodes.length} accent="green" />
          <MiniStat label="Host Links" value={edges.length} accent="purple" note="shared MITRE technique" />
        </div>
      </div>
    </Panel>
  )
}
