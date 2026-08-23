import type { ExplainResponse } from '../../api'
import { formatPercent } from '../../lib/format'
import { ErrorState, StatusPill } from '../ui'

interface EvidenceSourcePanelProps {
  status: 'idle' | 'loading' | 'success' | 'error'
  result: ExplainResponse | null
  error: string | null
  selfCritiqueFlagged: boolean
}

export function EvidenceSourcePanel({ status, result, error, selfCritiqueFlagged }: EvidenceSourcePanelProps) {
  if (status === 'idle' || status === 'loading') return null
  if (status === 'error') return <ErrorState message={error ?? 'Explain failed'} />
  if (!result) return null

  return (
    <div className="mt-4 space-y-4">
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold tracking-widest text-text-muted uppercase">Explanation</span>
        <StatusPill
          tone={selfCritiqueFlagged ? 'warn' : 'good'}
          label={selfCritiqueFlagged ? 'Self-critique flagged a claim' : 'Self-critique passed'}
        />
      </div>
      <p className="text-sm whitespace-pre-wrap text-text">{result.explanation}</p>

      <div>
        <span className="text-xs font-semibold tracking-widest text-text-muted uppercase">Recommended Response</span>
        <p className="mt-1 text-sm whitespace-pre-wrap text-text">{result.recommended_response}</p>
      </div>

      <div>
        <span className="text-xs font-semibold tracking-widest text-text-muted uppercase">Sources</span>
        <ul className="mt-1 space-y-1">
          {result.sources.map((source) => (
            <li
              key={source.chunk_id}
              className="flex items-center justify-between gap-3 rounded border border-border px-2 py-1 text-xs"
            >
              <span className="truncate text-text-muted">{source.document}</span>
              <span className="shrink-0 text-accent-cyan">{formatPercent(source.score * 100)}</span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  )
}
