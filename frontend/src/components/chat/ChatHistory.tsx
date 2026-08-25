import clsx from 'clsx'
import type { ChatTurn } from '../../hooks/useIncidentChat'
import { formatPercent } from '../../lib/format'
import { EmptyState, LoadingState } from '../ui'

interface ChatHistoryProps {
  turns: ChatTurn[]
  loading: boolean
}

export function ChatHistory({ turns, loading }: ChatHistoryProps) {
  if (loading) return <LoadingState label="Loading conversation" />
  if (turns.length === 0) return <EmptyState message="No messages yet -- ask a question below" />

  return (
    <ul className="max-h-96 space-y-3 overflow-y-auto pr-1">
      {turns.map((turn) => {
        const isUser = turn.role === 'user'
        return (
          <li key={turn.key} className={clsx('flex', isUser ? 'justify-end' : 'justify-start')}>
            <div
              className={clsx(
                'max-w-[85%] rounded border px-3 py-2 text-sm',
                isUser ? 'border-accent-cyan/30 bg-accent-cyan/10 text-text' : 'border-border bg-surface/60 text-text',
                turn.pending && 'opacity-60',
              )}
            >
              <div className="mb-1 text-[10px] tracking-widest text-text-muted uppercase">
                {isUser ? 'You' : 'NightOwl AI'}
                {turn.pending && ' · sending...'}
              </div>
              <p className="whitespace-pre-wrap">{turn.content}</p>
              {turn.sources && turn.sources.length > 0 && (
                <ul className="mt-2 space-y-1">
                  {turn.sources.map((source) => (
                    <li
                      key={source.chunk_id}
                      className="flex items-center justify-between gap-3 rounded border border-border px-2 py-1 text-xs"
                    >
                      <span className="truncate text-text-muted">{source.document}</span>
                      <span className="shrink-0 text-accent-cyan">{formatPercent(source.score * 100)}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </li>
        )
      })}
    </ul>
  )
}
