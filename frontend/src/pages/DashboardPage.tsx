// Full class strings, not template-literal interpolation -- Tailwind's JIT
// scanner only detects complete literal class names in source, not
// dynamically-built ones (e.g. `bg-severity-${severity}` would silently
// generate no CSS at all).
const SEVERITY_BADGE_CLASSES: Record<
  'informational' | 'low' | 'medium' | 'high' | 'critical',
  string
> = {
  informational: 'bg-severity-informational',
  low: 'bg-severity-low',
  medium: 'bg-severity-medium',
  high: 'bg-severity-high',
  critical: 'bg-severity-critical',
}

function DashboardPage() {
  return (
    <div className="p-6">
      <h1 className="text-2xl font-semibold text-slate-100">Dashboard</h1>
      <p className="mt-2 text-slate-400">
        Incident summary and recent activity land here.
      </p>

      {/* Proves the severity design tokens (src/index.css) are wired end to
          end -- Day 16 badges/Day 17 heatmap reuse these same classes. */}
      <div className="mt-4 flex gap-3">
        {(Object.keys(SEVERITY_BADGE_CLASSES) as Array<keyof typeof SEVERITY_BADGE_CLASSES>).map(
          (severity) => (
            <span
              key={severity}
              className={`rounded px-2 py-1 text-xs font-medium text-slate-950 ${SEVERITY_BADGE_CLASSES[severity]}`}
            >
              {severity}
            </span>
          ),
        )}
      </div>

      {/* TODO(Pair 2, Day 14 PM): <LogUploadForm /> goes here, wired to POST /ingest */}
    </div>
  )
}

export default DashboardPage
