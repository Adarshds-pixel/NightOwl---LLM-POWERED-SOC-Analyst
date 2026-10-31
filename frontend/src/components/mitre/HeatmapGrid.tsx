import clsx from 'clsx'
import type { IncidentSummary, MitreTechnique } from '../../api'
import { tacticTechniqueMatrix } from '../../lib/aggregations'
import { usePreferences } from '../../context/preferences/usePreferences'
import { TACTIC_IDS, TACTIC_LABELS, TACTIC_ORDER, type Tactic } from '../../lib/tactics'
import { heatColor, getHeatLegend } from '../../lib/tokens'
import { EmptyState, FloatingTooltip } from '../ui'

/**
 * Tactic columns x observed techniques. Only techniques with at least one
 * real detection are drawn -- never the full 858-entry catalog, which would
 * be a wall of empty cells pretending to be coverage.
 *
 * `showAllTactics` draws every tactic in `TACTIC_ORDER` instead of only the
 * ones with detections, dimming the empty ones. That is the coverage-map
 * reading: a tactic NightOwl has never detected is a real, meaningful gap,
 * and hiding the column would hide the gap. The dashboard's compact summary
 * leaves it off, because there it is a glanceable summary rather than a
 * coverage assessment.
 *
 * `compact` is the dashboard variant: smaller
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
  const { prefs } = usePreferences()
  const isLight = prefs.theme === 'light'
  const heatLegend = getHeatLegend(prefs.theme)
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
                className={clsx('flex flex-1 flex-col gap-1', compact ? 'min-w-[68px]' : 'min-w-[92px]')}
              >
                <button
                  type="button"
                  onClick={() => onSelectTactic?.(tactic)}
                  disabled={!onSelectTactic}
                  className={clsx(
                    'flex flex-col justify-center rounded-chip border px-1.5 py-1.5 text-left transition-all duration-200',
                    compact ? 'min-h-[40px]' : 'min-h-[52px]',
                    selected
                      ? 'border-accent-primary/50 bg-accent-primary/15 shadow-glow-primary'
                      : observed
                        ? 'border-line bg-surface-2/50 hover:border-accent-primary/35 hover:bg-surface-2/80'
                        : 'border-line-soft bg-surface-2/20',
                    !onSelectTactic && 'cursor-default',
                  )}
                >
                  <span
                    className={clsx(
                      'line-clamp-2 leading-tight font-semibold',
                      compact ? 'text-[9px]' : 'text-micro',
                      observed ? 'text-text-dim' : 'text-text-faint',
                    )}
                  >
                    {TACTIC_LABELS[tactic]}
                  </span>
                  {!compact && (
                    <span className="mt-0.5 block truncate font-mono text-[9px] leading-tight text-text-faint tabular-nums">
                      {TACTIC_IDS[tactic]}
                    </span>
                  )}
                  <span
                    className={clsx(
                      'mt-0.5 block truncate font-mono text-[9px] leading-tight tabular-nums',
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
                          style={{ background: heatColor(0, prefs.theme) }}
                        />
                      )
                    }
                    const color = heatColor(cell.count, prefs.theme)
                    return (
                      <FloatingTooltip
                        key={cell.techniqueId}
                        className="w-full"
                        label={`${cell.techniqueId} - ${cell.techniqueName}: ${cell.count} detection${cell.count === 1 ? '' : 's'}`}
                      >
                        <div
                          className={clsx(
                            'w-full origin-center rounded-[5px] border border-line-soft will-change-transform',
                            'transition-[transform,box-shadow,border-color] duration-150 ease-out',
                            'hover:z-10 hover:scale-[1.18] hover:border-border-active',
                            // Only intense cells earn a glow on hover -- a
                            // near-black "0" cell brightening would read as a
                            // bug, not a feature. `--cell-glow` is this cell's
                            // own colour, so the glow always matches its heat.
                            cell.count > 0 && 'hover:shadow-[0_0_14px_-2px_var(--cell-glow)]',
                            compact ? 'h-4' : 'h-6',
                          )}
                          style={{
                            background: color,
                            '--cell-glow': color,
                            animationName: 'rise',
                            animationDuration: '0.3s',
                            animationTimingFunction: 'ease-out',
                            animationFillMode: 'both',
                            animationDelay: `${Math.min(index, 10) * 18}ms`,
                          } as React.CSSProperties}
                        >
                          {!compact && (
                            <span
                              className={clsx(
                                'flex h-full items-center justify-center font-mono text-[9px] tabular-nums',
                                isLight && cell.count <= 2 ? 'font-semibold text-text' : 'text-white/90',
                              )}
                            >
                              {cell.techniqueId}
                            </span>
                          )}
                        </div>
                      </FloatingTooltip>
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
        {heatLegend.map((entry) => (
          <span key={entry.label} className="flex items-center gap-1 text-micro text-text-muted">
            <span className="h-2.5 w-4 rounded-[3px] border border-line-soft" style={{ background: entry.color }} />
            {entry.label}
          </span>
        ))}
      </div>
    </div>
  )
}
