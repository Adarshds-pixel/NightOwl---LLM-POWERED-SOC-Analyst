// Minimal prev/next page control for genuinely server-paginated lists (the
// Logs page is the first one in this app -- every other list page eager-
// fetches everything up to a cap instead, see lib/constants.ts).
export function Pagination({
  page,
  pageSize,
  total,
  onPageChange,
}: {
  page: number
  pageSize: number
  total: number
  onPageChange: (page: number) => void
}) {
  const pageCount = Math.max(1, Math.ceil(total / pageSize))
  const canPrev = page > 0
  const canNext = page < pageCount - 1

  return (
    <div className="flex items-center justify-between gap-4 text-xs text-text-muted">
      <span>
        Page {page + 1} of {pageCount} &middot; {total.toLocaleString()} total
      </span>
      <div className="flex gap-2">
        <button
          type="button"
          disabled={!canPrev}
          onClick={() => onPageChange(page - 1)}
          className="rounded border border-border px-3 py-1 font-medium tracking-wide uppercase transition-colors hover:border-accent-cyan/40 hover:text-text disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:border-border disabled:hover:text-text-muted"
        >
          Prev
        </button>
        <button
          type="button"
          disabled={!canNext}
          onClick={() => onPageChange(page + 1)}
          className="rounded border border-border px-3 py-1 font-medium tracking-wide uppercase transition-colors hover:border-accent-cyan/40 hover:text-text disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:border-border disabled:hover:text-text-muted"
        >
          Next
        </button>
      </div>
    </div>
  )
}
