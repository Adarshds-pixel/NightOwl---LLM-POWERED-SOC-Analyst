import { useEffect, useRef, useState, type FormEvent } from 'react'
import { useIncidentChat } from '../../hooks/useIncidentChat'
import { ErrorState, Panel } from '../ui'
import { ChatHistory } from './ChatHistory'

interface ChatPanelProps {
  incidentId: number
  initialMessage?: string
}

export function ChatPanel({ incidentId, initialMessage }: ChatPanelProps) {
  const { turns, loading, error, sending, sendError, send } = useIncidentChat(incidentId)
  const [draft, setDraft] = useState('')
  const autoSentRef = useRef(false)

  // Auto-sends a prefilled question (from AiAssistantPanel's dashboard
  // teaser) exactly once -- the ref guard survives StrictMode's double
  // effect invocation in dev.
  useEffect(() => {
    if (!initialMessage || autoSentRef.current) return
    autoSentRef.current = true
    send(initialMessage)
  }, [initialMessage, send])

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (!draft.trim()) return
    send(draft)
    setDraft('')
  }

  return (
    <Panel title="Incident Chat" accent="green">
      {error && <ErrorState message={error} />}
      {!error && <ChatHistory turns={turns} loading={loading} />}

      <form onSubmit={handleSubmit} className="mt-3 flex items-center gap-2">
        <input
          type="text"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          placeholder="Ask about this incident..."
          disabled={sending}
          className="flex-1 rounded border border-border bg-surface/60 px-3 py-2 text-sm text-text placeholder:text-text-muted focus:border-accent-green focus:outline-none disabled:opacity-60"
        />
        <button
          type="submit"
          disabled={sending || !draft.trim()}
          className="rounded border border-accent-green bg-accent-green/10 px-4 py-2 text-xs font-semibold tracking-widest text-accent-green uppercase disabled:opacity-50"
        >
          {sending ? 'Sending...' : 'Send'}
        </button>
      </form>
      {sendError && <p className="mt-2 text-xs text-accent-red">{sendError}</p>}
    </Panel>
  )
}
