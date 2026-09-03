import clsx from 'clsx'
import { Bot, ChevronDown, User } from 'lucide-react'
import { useState } from 'react'
import type { ChatTurn } from '../../hooks/useIncidentChat'
import { formatPercent, formatTimeOfDay } from '../../lib/format'
import { AIThinking, EmptyState, LoadingState, Markdown } from '../ui'

/**
 * The conversation. Assistant turns carry the retrieval sources the answer
 * was grounded in whenever the backend returned them (POST /chat does, the
 * stored history does not -- so a reloaded conversation shows the text
 * without claiming sources it cannot prove).
 */
export function ChatHistory({ turns, loading, sending }: { turns: ChatTurn[]; loading: boolean; sending?: boolean }) {
  if (loading) return <LoadingState label="Loading conversation" />
  if (turns.length === 0) {
    return (
      <EmptyState
        icon={<Bot className="h-5 w-5" />}
        message="No messages yet"
        hint="Ask about this incident, the technique behind it, or what to do next."
      />
    )
  }

  return (
    <ul className="flex flex-col gap-4">
      {turns.map((turn) => (
        <AIMessage key={turn.key} turn={turn} />
      ))}
      {sending && (
        <li>
          {/* One real POST /chat is in flight, so this states that plainly
              rather than narrating invented sub-steps. */}
          <AIThinking label="NightOwl AI is reasoning over this incident" />
        </li>
      )}
    </ul>
  )
}

/** One message bubble. Exported so the assistant page can reuse it. */
export function AIMessage({ turn }: { turn: ChatTurn }) {
  const [showSources, setShowSources] = useState(false)
  const isUser = turn.role === 'user'

  return (
    <li className={clsx('flex gap-2.5', isUser ? 'flex-row-reverse' : 'flex-row')}>
      <span
        className={clsx(
          'mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-full ring-1',
          isUser
            ? 'bg-accent-primary/15 text-accent-primary ring-accent-primary/25'
            : 'bg-accent-violet/15 text-accent-violet ring-accent-violet/25',
        )}
      >
        {isUser ? <User className="h-3.5 w-3.5" /> : <Bot className="h-3.5 w-3.5" />}
      </span>

      <div
        className={clsx(
          'max-w-[86%] min-w-0 rounded-card border px-3.5 py-2.5',
          isUser ? 'border-accent-primary/25 bg-accent-primary/8' : 'border-line bg-surface-2/50',
          turn.pending && 'opacity-60',
        )}
      >
        <div className="mb-1 flex items-center gap-2 text-micro tracking-[0.1em] text-text-faint uppercase">
          <span>{isUser ? 'You' : 'NightOwl AI'}</span>
          {turn.createdAt && <span className="font-mono">{formatTimeOfDay(turn.createdAt)}</span>}
          {turn.pending && <span>sending...</span>}
        </div>
        {isUser ? (
          <p className="text-body whitespace-pre-wrap text-text-dim">{turn.content}</p>
        ) : (
          <Markdown content={turn.content} />
        )}

        {turn.sources && turn.sources.length > 0 && (
          <div className="mt-2 border-t border-line-soft pt-2">
            <button
              type="button"
              onClick={() => setShowSources((open) => !open)}
              className="flex items-center gap-1 text-micro font-semibold tracking-wide text-accent-magenta uppercase"
            >
              {turn.sources.length} source{turn.sources.length === 1 ? '' : 's'}
              <ChevronDown className={clsx('h-3 w-3 transition-transform', showSources && 'rotate-180')} />
            </button>
            {showSources && (
              <ul className="mt-1.5 flex flex-col gap-1">
                {turn.sources.map((source) => (
                  <li key={source.chunk_id} className="flex items-start justify-between gap-2 text-micro">
                    <span className="line-clamp-2 text-text-muted">{source.document}</span>
                    <span className="shrink-0 font-mono text-accent-magenta tabular-nums">
                      {formatPercent(source.score * 100, 1)}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
      </div>
    </li>
  )
}
