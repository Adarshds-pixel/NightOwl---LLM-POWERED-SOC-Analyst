import { BookOpen, ShieldCheck, ShieldQuestion } from 'lucide-react'
import type { ExplainResponse } from '../../api'
import { formatPercent } from '../../lib/format'
import { Badge, Card, EmptyState, ErrorState, LoadingState, Markdown, MeterBar } from '../ui'
import { ACCENT } from '../../lib/tokens'

/**
 * The AI analysis result: explanation, recommended response, and the RAG
 * chunks that grounded them with their real similarity scores.
 *
 * The pass/flag pill is derived from whether the backend self-critique step
 * appended a confidence-check block to the explanation -- it is not a
 * fabricated confidence percentage, because the pipeline does not produce
 * one.
 */
export function EvidenceSourcePanel({
  status,
  result,
  error,
  selfCritiqueFlagged,
}: {
  status: 'idle' | 'loading' | 'success' | 'error'
  result: ExplainResponse | null
  error: string | null
  selfCritiqueFlagged: boolean
}) {
  if (status === 'loading') return <LoadingState label="Running retrieval, drafting and self-critique" />
  if (status === 'error') return <ErrorState message={error ?? 'Explain failed'} />
  if (status === 'idle' || !result) {
    return (
      <EmptyState
        icon={<BookOpen className="h-5 w-5" />}
        message="No AI analysis run yet"
        hint="Run the analysis to retrieve MITRE context, draft an explanation and self-critique it."
      />
    )
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="text-meta font-semibold tracking-[0.12em] text-text-dim uppercase">Explanation</h3>
        <Badge accent={selfCritiqueFlagged ? 'amber' : 'green'}>
          {selfCritiqueFlagged ? (
            <>
              <ShieldQuestion className="h-3 w-3" /> Self-critique flagged a claim
            </>
          ) : (
            <>
              <ShieldCheck className="h-3 w-3" /> Self-critique passed
            </>
          )}
        </Badge>
      </div>
      <Markdown content={result.explanation} />

      {result.recommended_response && (
        <Card title="Recommended response" accent="green" className="bg-surface-2/40">
          <Markdown content={result.recommended_response} />
        </Card>
      )}

      <div>
        <h3 className="mb-2 text-meta font-semibold tracking-[0.12em] text-text-dim uppercase">
          Sources and references
        </h3>
        <ul className="flex flex-col gap-1.5">
          {result.sources.map((source) => (
            <li key={source.chunk_id} className="rounded-control border border-line bg-surface-2/40 px-3 py-2">
              <div className="flex items-start justify-between gap-3">
                <p className="line-clamp-2 text-meta text-text-muted">{source.document}</p>
                <span className="shrink-0 font-mono text-micro text-accent-cyan tabular-nums">
                  {formatPercent(source.score * 100, 1)}
                </span>
              </div>
              <MeterBar className="mt-1.5" value={source.score * 100} color={ACCENT.cyan} />
            </li>
          ))}
        </ul>
        <p className="mt-1.5 text-micro text-text-faint">
          Similarity score from the knowledge-base retrieval, not a confidence rating.
        </p>
      </div>
    </div>
  )
}
