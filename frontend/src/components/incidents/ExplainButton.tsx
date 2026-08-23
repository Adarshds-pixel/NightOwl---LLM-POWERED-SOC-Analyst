import { EXPLAIN_STAGES, type ExplainStatus } from '../../hooks/useExplain'

interface ExplainButtonProps {
  status: ExplainStatus
  stageIndex: number
  onRun: () => void
}

export function ExplainButton({ status, stageIndex, onRun }: ExplainButtonProps) {
  const loading = status === 'loading'
  return (
    <div className="flex items-center gap-3">
      <button
        type="button"
        onClick={onRun}
        disabled={loading}
        className="shadow-glow-purple rounded border border-accent-purple bg-accent-purple/10 px-4 py-2 text-sm font-semibold tracking-wide text-accent-purple uppercase disabled:opacity-60"
      >
        {loading ? 'Analyzing...' : 'Explain This Incident'}
      </button>
      {loading && (
        <span className="animate-pulse text-xs tracking-wide text-text-muted">{EXPLAIN_STAGES[stageIndex]}</span>
      )}
    </div>
  )
}
