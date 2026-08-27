import { Sparkles } from 'lucide-react'
import { EXPLAIN_STAGES, type ExplainStatus } from '../../hooks/useExplain'
import { Button, TypingDots } from '../ui'

/**
 * Runs POST /incidents/{id}/explain. The stage caption narrates what that
 * single request is actually doing server-side (retrieve, draft,
 * self-critique) -- it never implies a result before one arrives.
 */
export function ExplainButton({
  status,
  stageIndex,
  onRun,
}: {
  status: ExplainStatus
  stageIndex: number
  onRun: () => void
}) {
  const loading = status === 'loading'

  return (
    <div className="flex flex-wrap items-center gap-3">
      <Button variant="primary" onClick={onRun} disabled={loading} icon={<Sparkles className="h-3.5 w-3.5" />}>
        {loading ? 'Analysing...' : status === 'success' ? 'Re-run AI analysis' : 'Explain this incident'}
      </Button>
      {loading && (
        <span className="flex items-center gap-2 text-meta text-text-muted">
          <TypingDots />
          {EXPLAIN_STAGES[stageIndex]}
        </span>
      )}
    </div>
  )
}
