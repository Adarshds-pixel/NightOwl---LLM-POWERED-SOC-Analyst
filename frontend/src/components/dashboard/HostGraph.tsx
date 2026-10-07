import { useId } from 'react'
import type { HostEdge, HostNode } from '../../lib/aggregations'
import { SEVERITY_HEX } from '../../lib/severity'
import { ACCENT, LINE } from '../../lib/tokens'
import { EmptyState, Tooltip } from '../ui'

const WIDTH = 380
const HEIGHT = 268
const CENTER_X = WIDTH / 2
const CENTER_Y = HEIGHT / 2
const LAYOUT_RADIUS = 92

/**
 * Internal host-activity graph: one node per host that has incidents, sized
 * by incident count, coloured by worst severity, joined where two hosts
 * share a MITRE technique.
 *
 * This is the panel that occupies the slot a world "threat map" would take
 * in a generic SOC template. NightOwl has no geolocation data of any kind
 * (it ingests local Windows event logs), so a globe with attack arcs would
 * be pure decoration; the real lateral relationship between hosts is both
 * honest and more useful.
 */

function nodeRadius(incidentCount: number): number {
  return 9 + Math.min(incidentCount, 8) * 1.8
}

function edgeWidth(sharedTechniqueCount: number): number {
  return 1 + Math.min(sharedTechniqueCount, 4)
}

// Deterministic circular layout -- angle is purely a function of each node's
// fixed position in the (already deterministically sorted) array, never
// randomised or force-simulated, so the graph does not reshuffle on every
// refresh.
function layoutPositions(nodes: HostNode[]): Map<string, { x: number; y: number }> {
  const positions = new Map<string, { x: number; y: number }>()
  if (nodes.length === 1) {
    positions.set(nodes[0].host, { x: CENTER_X, y: CENTER_Y })
    return positions
  }
  nodes.forEach((node, i) => {
    const angle = -Math.PI / 2 + (i / nodes.length) * 2 * Math.PI
    positions.set(node.host, {
      x: CENTER_X + LAYOUT_RADIUS * Math.cos(angle),
      y: CENTER_Y + LAYOUT_RADIUS * Math.sin(angle),
    })
  })
  return positions
}

export function HostGraph({ nodes, edges }: { nodes: HostNode[]; edges: HostEdge[] }) {
  const glowId = useId()

  if (nodes.length === 0) {
    return <EmptyState message="No host activity yet" hint="Ingest logs to populate the host graph." />
  }

  const positions = layoutPositions(nodes)

  return (
    <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} className="w-full" style={{ maxHeight: HEIGHT }} role="img" aria-label="Host activity graph">
      <defs>
        <radialGradient id={glowId}>
          <stop offset="0%" stopColor={ACCENT.primary} stopOpacity="0.18" />
          <stop offset="100%" stopColor={ACCENT.primary} stopOpacity="0" />
        </radialGradient>
      </defs>
      <circle cx={CENTER_X} cy={CENTER_Y} r={LAYOUT_RADIUS + 40} fill={`url(#${glowId})`} />
      <circle cx={CENTER_X} cy={CENTER_Y} r={LAYOUT_RADIUS} fill="none" stroke={LINE.base} strokeDasharray="3 5" />

      {edges.map((edge) => {
        const a = positions.get(edge.a)
        const b = positions.get(edge.b)
        if (!a || !b) return null
        return (
          <line
            key={`${edge.a}-${edge.b}`}
            x1={a.x}
            y1={a.y}
            x2={b.x}
            y2={b.y}
            stroke={ACCENT.magenta}
            strokeOpacity={0.22}
            strokeWidth={edgeWidth(edge.sharedTechniqueCount)}
            strokeLinecap="round"
          />
        )
      })}

      {nodes.map((node) => {
        const pos = positions.get(node.host)
        if (!pos) return null
        const r = nodeRadius(node.incidentCount)
        const color = SEVERITY_HEX[node.severity]
        return (
          <g key={node.host}>
            <title>{`${node.host}: ${node.incidentCount} incident(s), worst severity ${node.severity}`}</title>
            <circle cx={pos.x} cy={pos.y} r={r + 5} fill={color} fillOpacity={0.12} />
            <circle cx={pos.x} cy={pos.y} r={r} fill={color} fillOpacity={0.9} stroke={color} strokeWidth={1.5} />
            <text x={pos.x} y={pos.y + 3.5} textAnchor="middle" className="fill-bg-deep text-[10px] font-bold">
              {node.incidentCount}
            </text>
            <text x={pos.x} y={pos.y + r + 13} textAnchor="middle" className="fill-current text-[9px] tracking-wide text-text-muted uppercase">
              {node.host}
            </text>
          </g>
        )
      })}
    </svg>
  )
}

/** Legend explaining what node size, colour and edges mean -- without it
 *  the graph is decorative rather than readable. */
export function HostGraphLegend() {
  return (
    <ul className="flex flex-wrap items-center gap-x-4 gap-y-1 text-micro text-text-muted">
      <li className="flex items-center gap-1.5">
        <span className="h-2.5 w-2.5 rounded-full bg-severity-critical" />
        Worst severity on host
      </li>
      <li className="flex items-center gap-1.5">
        <span className="h-2.5 w-2.5 rounded-full border border-text-muted" />
        Size = incident count
      </li>
      <li className="flex items-center gap-1.5">
        <span className="h-0.5 w-4 rounded-full bg-accent-magenta/60" />
        Shared MITRE technique
      </li>
      <Tooltip label="Hosts are joined when the same ATT&CK technique was detected on both. A shared technique is a lead worth checking, not proof of lateral movement.">
        <li className="cursor-help text-text-faint underline decoration-dotted">What does an edge mean?</li>
      </Tooltip>
    </ul>
  )
}
