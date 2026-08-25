import { useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { useIncidentsSnapshot } from '../../context/incidents/useIncidentsSnapshot'
import { selectMostActionableIncident } from '../../lib/aggregations'
import { EmptyState, Panel } from '../ui'

// An honest teaser, not a standalone assistant -- there is no global chat
// endpoint. Submitting routes the typed question into the most actionable
// open incident's REAL chat (POST /incidents/{id}/chat, via ChatPanel's
// initialMessage prop) rather than fabricating a reply here.
export function AiAssistantPanel() {
  const { incidents } = useIncidentsSnapshot()
  const navigate = useNavigate()
  const [question, setQuestion] = useState('')

  const target = selectMostActionableIncident(incidents)

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    const trimmed = question.trim()
    if (!trimmed || !target) return
    navigate(`/incidents/${target.id}`, { state: { prefillChatMessage: trimmed } })
  }

  return (
    <Panel title="Ask NightOwl AI" accent="purple">
      {!target ? (
        <EmptyState message="No open incident to discuss yet" />
      ) : (
        <form onSubmit={handleSubmit} className="flex flex-col gap-2">
          <p className="text-xs text-text-muted">
            Ask about <span className="text-text">{target.title}</span> -- routes into that incident&apos;s real chat.
          </p>
          <div className="flex items-center gap-2">
            <input
              type="text"
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              placeholder="e.g. how do I contain this?"
              className="flex-1 rounded border border-border bg-surface/60 px-3 py-2 text-sm text-text placeholder:text-text-muted focus:border-accent-purple focus:outline-none"
            />
            <button
              type="submit"
              disabled={!question.trim()}
              className="rounded border border-accent-purple bg-accent-purple/10 px-4 py-2 text-xs font-semibold tracking-widest text-accent-purple uppercase disabled:opacity-50"
            >
              Ask
            </button>
          </div>
        </form>
      )}
    </Panel>
  )
}
