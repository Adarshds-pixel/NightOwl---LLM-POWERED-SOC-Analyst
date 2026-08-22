import { SEVERITY_HEX } from '../../lib/severity'
import type { HostEdge, HostNode } from '../../lib/aggregations'
import { EmptyState } from '../ui'

const WIDTH = 420
const HEIGHT = 300
const CENTER_X = WIDTH / 2
const CENTER_Y = HEIGHT / 2
const LAYOUT_RADIUS = 100

function nodeRadius(incidentCount: number): number {
  return 10 + Math.min(incidentCount, 8) * 2
}

function edgeWidth(sharedTechniqueCount: number): number {
  return 1 + Math.min(sharedTechniqueCount, 5)
}

// Deterministic circular layout -- angle is purely a function of each
// node's fixed position in the (already deterministically-sorted, see
// lib/aggregations.ts) array, never randomized or force-simulated.
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
  if (nodes.length === 0) {
    return <EmptyState message="No host activity yet -- ingest logs to populate the graph" />
  }

  const positions = layoutPositions(nodes)

  return (
    <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} className="w-full" style={{ maxHeight: HEIGHT }}>
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
            className="stroke-accent-cyan"
            strokeOpacity={0.25}
            strokeWidth={edgeWidth(edge.sharedTechniqueCount)}
          />
        )
      })}
      {nodes.map((node) => {
        const pos = positions.get(node.host)
        if (!pos) return null
        const r = nodeRadius(node.incidentCount)
        return (
          <g key={node.host}>
            <circle cx={pos.x} cy={pos.y} r={r} fill={SEVERITY_HEX[node.severity]} fillOpacity={0.85} />
            <circle cx={pos.x} cy={pos.y} r={r} fill="none" stroke={SEVERITY_HEX[node.severity]} strokeWidth={1.5} />
            <text
              x={pos.x}
              y={pos.y + r + 14}
              textAnchor="middle"
              className="fill-text font-display text-[10px] uppercase"
            >
              {node.host}
            </text>
            <text x={pos.x} y={pos.y + 4} textAnchor="middle" className="fill-bg text-[10px] font-bold">
              {node.incidentCount}
            </text>
          </g>
        )
      })}
    </svg>
  )
}
