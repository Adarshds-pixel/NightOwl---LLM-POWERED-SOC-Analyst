import clsx from 'clsx'
import { ChevronLeft, ChevronRight } from 'lucide-react'
import { PAGE_SIZE_OPTIONS } from '../../lib/preferences'

/**
 * Numbered pagination matching the mockups: a "showing X to Y of Z" line on
 * the left, page buttons with ellipsis in the middle and a page-size select
 * on the right. Page indices are zero-based to match the API offset maths;
 * only the labels are one-based.
 */
export function Pagination({
  page,
  pageSize,
  total,
  onPageChange,
  onPageSizeChange,
  itemLabel = 'items',
  className,
}: {
  page: number
  pageSize: number
  total: number
  onPageChange: (page: number) => void
  onPageSizeChange?: (size: number) => void
  itemLabel?: string
  className?: string
}) {
  const pageCount = Math.max(1, Math.ceil(total / pageSize))
  const first = total === 0 ? 0 : page * pageSize + 1
  const last = Math.min(total, (page + 1) * pageSize)

  return (
    <div
      className={clsx(
        'flex flex-wrap items-center justify-between gap-3 border-t border-line-soft px-4 py-3 text-meta text-text-muted',
        className,
      )}
    >
      <span>
        Showing <span className="font-mono text-text-dim tabular-nums">{first}</span> to{' '}
        <span className="font-mono text-text-dim tabular-nums">{last}</span> of{' '}
        <span className="font-mono text-text-dim tabular-nums">{total.toLocaleString()}</span> {itemLabel}
      </span>

      <div className="flex items-center gap-2">
        <nav aria-label="Pagination" className="flex items-center gap-1">
          <PageButton
            onClick={() => onPageChange(page - 1)}
            disabled={page === 0}
            label="Previous page"
            icon={<ChevronLeft className="h-3.5 w-3.5" />}
          />
          {pageNumbers(page, pageCount).map((entry, i) =>
            entry === null ? (
              <span key={`gap-${i}`} className="px-1 text-text-faint">
                ...
              </span>
            ) : (
              <button
                key={entry}
                type="button"
                onClick={() => onPageChange(entry)}
                aria-current={entry === page ? 'page' : undefined}
                className={clsx(
                  'h-7 min-w-7 rounded-md border px-2 font-mono text-micro tabular-nums transition-colors duration-200',
                  entry === page
                    ? 'border-accent-violet/50 bg-accent-violet/25 text-text'
                    : 'border-line bg-surface-2/50 text-text-muted hover:border-accent-primary/40 hover:text-text',
                )}
              >
                {entry + 1}
              </button>
            ),
          )}
          <PageButton
            onClick={() => onPageChange(page + 1)}
            disabled={page >= pageCount - 1}
            label="Next page"
            icon={<ChevronRight className="h-3.5 w-3.5" />}
          />
        </nav>

        {onPageSizeChange && (
          <select
            value={pageSize}
            onChange={(e) => onPageSizeChange(Number(e.target.value))}
            aria-label="Rows per page"
            className="h-7 cursor-pointer rounded-md border border-line bg-surface-2/50 px-2 text-micro text-text-muted transition-colors hover:text-text focus:outline-none"
          >
            {PAGE_SIZE_OPTIONS.map((size) => (
              <option key={size} value={size} className="bg-surface-2 text-text">
                {size} / page
              </option>
            ))}
          </select>
        )}
      </div>
    </div>
  )
}

function PageButton({
  onClick,
  disabled,
  label,
  icon,
}: {
  onClick: () => void
  disabled: boolean
  label: string
  icon: React.ReactNode
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      aria-label={label}
      className="flex h-7 w-7 items-center justify-center rounded-md border border-line bg-surface-2/50 text-text-muted transition-colors duration-200 hover:border-accent-primary/40 hover:text-text disabled:cursor-not-allowed disabled:opacity-40"
    >
      {icon}
    </button>
  )
}

/** Windowed page list: always the first and last page, the current page and
 *  its neighbours, ellipsis for the gaps. */
function pageNumbers(page: number, pageCount: number): (number | null)[] {
  if (pageCount <= 7) return Array.from({ length: pageCount }, (_, i) => i)

  const pages = new Set<number>([0, pageCount - 1, page])
  if (page > 0) pages.add(page - 1)
  if (page < pageCount - 1) pages.add(page + 1)

  const sorted = [...pages].sort((a, b) => a - b)
  const result: (number | null)[] = []
  let previous = -1
  for (const value of sorted) {
    if (previous >= 0 && value - previous > 1) result.push(null)
    result.push(value)
    previous = value
  }
  return result
}
