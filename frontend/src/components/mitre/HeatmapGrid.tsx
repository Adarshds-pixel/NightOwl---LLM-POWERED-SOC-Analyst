import clsx from 'clsx'
import type { IncidentSummary, MitreTechnique } from '../../api'
import { tacticTechniqueMatrix } from '../../lib/aggregations'
import { TACTIC_IDS, TACTIC_LABELS, TACTIC_ORDER, type Tactic } from '../../lib/tactics'
import { heatColor, HEAT_LEGEND } from '../../lib/tokens'
import { EmptyState, Tooltip } from '../ui'

/**
 * Tactic columns x observed techniques. Only techniques with at least one
 * real detection are drawn -- never the full 858-entry catalog, which would
 * be a wall of empty cells pretending to be coverage.
 *
 * `showAllTactics` draws all 14 enterprise tactics instead of only the ones
 * with detections, dimming the empty ones. That is the coverage-map reading:
 * a tactic NightOwl has never detected is a real, meaningful gap, and hiding
 * the column would hide the gap. The dashboard's compact summary leaves it
 * off, because there it is a glanceable summary rather than a coverage
 * assessment.
 *
 * `compact` is the dashboard variant: abbreviated tactic labels, smaller
 * cells, a capped number of rows.
 */
export function HeatmapGrid({
  incidents,
  techniqueById,
  compact = false,
  showAllTactics = false,
  maxRows,
  onSelectTactic,
  selectedTactic,
}: {
  incidents: IncidentSummary[]
  techniqueById: Map<string, MitreTechnique>
  compact?: boolean
  showAllTactics?: boolean
  maxRows?: number
  onSelectTactic?: (tactic: Tactic) => void
  selectedTactic?: Tactic | null
}) {
  const { cells, tacticsPresent } = tacticTechniqueMatrix(incidents, techniqueById)

  if (cells.length === 0 && !showAllTactics) {
    return <EmptyState message="No MITRE techniques observed yet" hint="Ingest logs to populate the matrix." />
  }

  const columns = showAllTactics ? [...TACTIC_ORDER] : TACTIC_ORDER.filter((tactic) => tacticsPresent.includes(tactic))
  const byTactic = new Map<Tactic, typeof cells>()
  for (const cell of cells) {
    const list = byTactic.get(cell.tactic) ?? []
    list.push(cell)
    byTactic.set(cell.tactic, list)
  }
  for (const list of byTactic.values()) list.sort((a, b) => b.count - a.count)

  // A minimum height keeps the matrix a consistent block instead of
  // collapsing to two or three rows when one tactic happens to dominate.
  const observedMax = Math.max(0, ...columns.map((tactic) => byTactic.get(tactic)?.length ?? 0))
  const rowCount = Math.min(maxRows ?? Number.MAX_SAFE_INTEGER, Math.max(observedMax, showAllTactics ? 6 : 1))

  return (
    <div className="flex flex-col gap-3">
      {/* Columns flex to fill the card; the min widths below are the point at
          which this scrolls instead of crushing the cells. */}
      <div className="overflow-x-auto">
        <div className="flex gap-1.5">
          {columns.map((tactic) => {
            const techniques = byTactic.get(tactic) ?? []
            const total = techniques.reduce((sum, cell) => sum + cell.count, 0)
            const selected = selectedTactic === tactic
            const observed = techniques.length > 0
            return (
              <div
                key={tactic}
                className={clsx('flex flex-1 flex-col gap-1', compact ? 'min-w-[56px]' : 'min-w-[76px]')}
              >
                <button
                  type="button"
                  onClick={() => onSelectTactic?.(tactic)}
                  disabled={!onSelectTactic}
                  className={clsx(
                    'rounded-chip border px-1.5 py-1.5 text-left transition-colors duration-200',
                    selected
                      ? 'border-accent-blue/50 bg-accent-blue/15'
                      : observed
                        ? 'border-line bg-surface-2/50 hover:border-accent-blue/30'
                        : 'border-line-soft bg-surface-2/20',
                    !onSelectTactic && 'cursor-default',
                  )}
                >
                  <span
                    className={clsx(
                      'block leading-tight font-semibold',
                      compact ? 'text-[9px]' : 'text-micro',
                      observed ? 'text-text-dim' : 'text-text-faint',
                    )}
                  >
                    {compact ? shortLabel(tactic) : TACTIC_LABELS[tactic]}
                  </span>
                  {!compact && (
                    <span className="mt-0.5 block font-mono text-[9px] text-text-faint tabular-nums">
                      {TACTIC_IDS[tactic]}
                    </span>
                  )}
                  <span
                    className={clsx(
                      'mt-0.5 block font-mono text-[9px] tabular-nums',
                      observed ? 'text-text-faint' : 'text-text-faint/60',
                    )}
                  >
                    {techniques.length} tech - {total} hits
                  </span>
                </button>

                <div className="flex flex-col gap-1">
                  {Array.from({ length: rowCount }).map((_, index) => {
                    const cell = techniques[index]
                    if (!cell) {
                      return (
                        <div
                          key={index}
                          className={clsx('rounded-[5px] border border-line-soft', compact ? 'h-4' : 'h-6')}
                          style={{ background: heatColor(0) }}
                        />
                      )
                    }
                    return (
                      <Tooltip
                        key={cell.techniqueId}
                        label={`${cell.techniqueId} - ${cell.techniqueName}: ${cell.count} detection${cell.count === 1 ? '' : 's'}`}
                      >
                        <div
                          className={clsx(
                            'w-full rounded-[5px] border border-white/5 transition-transform duration-150 hover:scale-[1.04]',
                            compact ? 'h-4' : 'h-6',
                          )}
                          style={{ background: heatColor(cell.count) }}
                        >
                          {!compact && (
                            <span className="flex h-full items-center justify-center font-mono text-[9px] text-white/85 tabular-nums">
                              {cell.techniqueId}
                            </span>
                          )}
                        </div>
                      </Tooltip>
                    )
                  })}
                </div>
              </div>
            )
          })}
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <span className="text-micro tracking-wide text-text-faint uppercase">Detections</span>
        {HEAT_LEGEND.map((entry) => (
          <span key={entry.label} className="flex items-center gap-1 text-micro text-text-muted">
            <span className="h-2.5 w-4 rounded-[3px] border border-white/5" style={{ background: entry.color }} />
            {entry.label}
          </span>
        ))}
      </div>
    </div>
  )
}

/** Two-letter-ish tactic abbreviations for the dashboard variant, matching
 *  the way the mockup labels its compact matrix columns. */
function shortLabel(tactic: Tactic): string {
  return TACTIC_LABELS[tactic]
    .split(/[\s-]/)
    .map((word) => word[0])
    .join('')
    .toUpperCase()
}
