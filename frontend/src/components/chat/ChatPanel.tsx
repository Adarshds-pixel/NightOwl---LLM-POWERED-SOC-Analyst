import { MessagesSquare } from 'lucide-react'
import { useEffect, useRef } from 'react'
import { useIncidentChat } from '../../hooks/useIncidentChat'
import { Card, ErrorState } from '../ui'
import { ChatHistory } from './ChatHistory'
import { CommandInput } from './CommandInput'

/**
 * Incident-scoped chat (GET/POST /incidents/{id}/chat). Every reply is a
 * real RAG call against that incident, so the panel always says which
 * incident it is talking about.
 */
export function ChatPanel({
  incidentId,
  initialMessage,
  className,
}: {
  incidentId: number
  initialMessage?: string
  className?: string
}) {
  const { turns, loading, error, sending, sendError, send, refresh } = useIncidentChat(incidentId)
  const autoSentRef = useRef(false)
  const scrollRef = useRef<HTMLDivElement>(null)

  // Auto-sends a prefilled question (from the dashboard assistant card)
  // exactly once -- the ref guard survives StrictMode double effects.
  useEffect(() => {
    if (!initialMessage || autoSentRef.current) return
    autoSentRef.current = true
    send(initialMessage)
  }, [initialMessage, send])

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: 'smooth' })
  }, [turns.length, sending])

  return (
    <Card title="Incident chat" icon={<MessagesSquare className="h-3.5 w-3.5" />} accent="violet" className={className}>
      {error ? (
        <ErrorState message={error} onRetry={refresh} />
      ) : (
        <div ref={scrollRef} className="max-h-96 overflow-y-auto pr-1">
          <ChatHistory turns={turns} loading={loading} sending={sending} />
        </div>
      )}

      <div className="mt-3">
        <CommandInput
          onSubmit={send}
          disabled={sending || Boolean(error)}
          placeholder="Ask about this incident..."
          note={sendError ?? 'Answers are grounded in the MITRE knowledge base; verify before acting.'}
        />
      </div>
    </Card>
  )
}
