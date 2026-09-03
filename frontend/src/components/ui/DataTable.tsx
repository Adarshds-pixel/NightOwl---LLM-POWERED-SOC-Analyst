import clsx from 'clsx'
import { ArrowDown, ArrowUp, ChevronsUpDown } from 'lucide-react'
import type { ReactNode } from 'react'
import { usePreferences } from '../../context/preferences/usePreferences'
import { EmptyState, ErrorState, SkeletonRows } from './states'

/**
 * The one table in NightOwl. Every list page configures columns and hands
 * over rows; nobody writes raw <table> markup any more (there used to be
 * three near-identical copies of the same thead styling).
 *
 * Deliberately unopinionated about data fetching: sorting is client-side
 * over whatever page of rows it is given, because neither GET /incidents
 * nor GET /events accepts a sort parameter -- so sorting a paginated table
 * sorts the current page, and pages that need global ordering fetch
 * everything first (see IncidentsDataProvider).
 */

export interface Column<T> {
  key: string
  header: ReactNode
  /** Cell renderer. */
  cell: (row: T) => ReactNode
  /** Provide to make the column sortable. */
  sortValue?: (row: T) => string | number
  className?: string
  headerClassName?: string
  /** Hidden below this Tailwind breakpoint, e.g. "lg" -> hidden below lg. */
  hideBelow?: 'sm' | 'md' | 'lg' | 'xl'
  align?: 'left' | 'right' | 'center'
}

export interface SortState {
  key: string
  direction: 'asc' | 'desc'
}

interface DataTableProps<T> {
  columns: Column<T>[]
  rows: T[]
  rowKey: (row: T) => string | number
  onRowClick?: (row: T) => void
  isRowActive?: (row: T) => boolean
  sort?: SortState | null
  onSortChange?: (sort: SortState | null) => void
  loading?: boolean
  error?: string | null
  onRetry?: () => void
  emptyMessage?: string
  emptyHint?: string
  /** Sticky header inside a scroll container. */
  stickyHeader?: boolean
  /** A CSS colour for a row's left-edge marker (e.g. SEVERITY_HEX[row.severity]),
   *  or null/undefined for no marker. A generic colour rather than an Accent
   *  keeps this primitive independent of the severity vocabulary -- callers
   *  already own that mapping. */
  rowAccent?: (row: T) => string | null | undefined
  className?: string
}

const HIDE_BELOW: Record<NonNullable<Column<unknown>['hideBelow']>, string> = {
  sm: 'hidden sm:table-cell',
  md: 'hidden md:table-cell',
  lg: 'hidden lg:table-cell',
  xl: 'hidden xl:table-cell',
}

const ALIGN = {
  left: 'text-left',
  right: 'text-right',
  center: 'text-center',
} as const

export function DataTable<T>({
  columns,
  rows,
  rowKey,
  onRowClick,
  isRowActive,
  sort,
  onSortChange,
  loading,
  error,
  onRetry,
  emptyMessage = 'Nothing to show yet',
  emptyHint,
  stickyHeader = true,
  rowAccent,
  className,
}: DataTableProps<T>) {
  const { prefs } = usePreferences()
  const rowPadding = prefs.density === 'compact' ? 'py-1.5' : 'py-2.5'

  if (loading) return <SkeletonRows rows={6} />
  if (error) return <ErrorState message={error} onRetry={onRetry} />
  if (rows.length === 0) return <EmptyState message={emptyMessage} hint={emptyHint} />

  const sorted = applySort(rows, columns, sort)

  return (
    <div className={clsx('w-full overflow-x-auto', className)}>
      <table className="w-full min-w-full border-collapse text-body">
        <thead className={clsx(stickyHeader && 'sticky top-0 z-10')}>
          <tr className="bg-surface-2/85 backdrop-blur-[var(--blur-glass)] backdrop-saturate-[1.2]">
            {columns.map((column) => (
              <th
                key={column.key}
                scope="col"
                aria-sort={
                  sort?.key === column.key ? (sort.direction === 'asc' ? 'ascending' : 'descending') : undefined
                }
                className={clsx(
                  'border-b border-line px-3 py-2.5 text-micro font-semibold tracking-[0.12em] text-text-muted uppercase',
                  ALIGN[column.align ?? 'left'],
                  column.hideBelow && HIDE_BELOW[column.hideBelow],
                  column.headerClassName,
                )}
              >
                {column.sortValue && onSortChange ? (
                  <button
                    type="button"
                    onClick={() => onSortChange(nextSort(sort, column.key))}
                    className="inline-flex items-center gap-1 tracking-[0.12em] uppercase transition-colors hover:text-text"
                  >
                    {column.header}
                    <SortIcon active={sort?.key === column.key} direction={sort?.direction} />
                  </button>
                ) : (
                  column.header
                )}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.map((row) => {
            const active = isRowActive?.(row)
            const accent = rowAccent?.(row)
            return (
              <tr
                key={rowKey(row)}
                onClick={onRowClick ? () => onRowClick(row) : undefined}
                onKeyDown={
                  onRowClick
                    ? (e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.preventDefault()
                          onRowClick(row)
                        }
                      }
                    : undefined
                }
                tabIndex={onRowClick ? 0 : undefined}
                className={clsx(
                  'group/row border-b border-line-soft transition-colors duration-150 last:border-b-0',
                  onRowClick && 'cursor-pointer hover:bg-accent-primary/6 focus-visible:bg-accent-primary/6',
                  active && 'bg-accent-primary/8',
                )}
              >
                {columns.map((column, i) => (
                  <td
                    key={column.key}
                    className={clsx(
                      'relative px-3 align-middle text-text-dim',
                      rowPadding,
                      ALIGN[column.align ?? 'left'],
                      column.hideBelow && HIDE_BELOW[column.hideBelow],
                      column.className,
                    )}
                  >
                    {/* Severity/status edge marker -- a coloured bar on the
                        row's leading cell, so a critical row reads at a
                        glance without colouring the whole row. Brightens
                        with the row on hover via the group above. */}
                    {i === 0 && accent && (
                      <span
                        aria-hidden
                        className="absolute inset-y-0 left-0 w-[3px] opacity-70 shadow-[0_0_0_0_var(--row-accent)] transition-[opacity,box-shadow] duration-150 group-hover/row:opacity-100 group-hover/row:shadow-[0_0_8px_0_var(--row-accent)]"
                        style={{ background: accent, '--row-accent': accent } as React.CSSProperties}
                      />
                    )}
                    {column.cell(row)}
                  </td>
                ))}
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function SortIcon({ active, direction }: { active?: boolean; direction?: 'asc' | 'desc' }) {
  if (!active) return <ChevronsUpDown className="h-3 w-3 text-text-faint" />
  return direction === 'asc' ? (
    <ArrowUp className="h-3 w-3 text-accent-primary" />
  ) : (
    <ArrowDown className="h-3 w-3 text-accent-primary" />
  )
}

/** asc -> desc -> unsorted, so a user can always get back to the server
 *  ordering (newest first) without reloading. */
function nextSort(current: SortState | null | undefined, key: string): SortState | null {
  if (!current || current.key !== key) return { key, direction: 'asc' }
  if (current.direction === 'asc') return { key, direction: 'desc' }
  return null
}

function applySort<T>(rows: T[], columns: Column<T>[], sort: SortState | null | undefined): T[] {
  if (!sort) return rows
  const column = columns.find((c) => c.key === sort.key)
  if (!column?.sortValue) return rows

  const getValue = column.sortValue
  return [...rows].sort((a, b) => {
    const left = getValue(a)
    const right = getValue(b)
    const cmp = typeof left === 'number' && typeof right === 'number' ? left - right : String(left).localeCompare(String(right))
    return sort.direction === 'asc' ? cmp : -cmp
  })
}
