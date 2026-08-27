import clsx from 'clsx'
import { Check, MessageSquare, SendHorizontal, Sparkles } from 'lucide-react'
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import type { IncidentSummary } from '../../api'
import { useHealth } from '../../context/health/useHealth'
import { EXPLAIN_STAGES, useExplain } from '../../hooks/useExplain'
import { incidentRef } from '../../lib/format'
import { Badge, Button, Card, EmptyState, SeverityBadge, TypingDots } from '../ui'

/**
 * The AI Security Assistant card.
 *
 * The terminal is not decoration: each line is a stage of the real
 * POST /incidents/{id}/explain pipeline (retrieve -> draft -> self-critique)
 * for the incident named above it, and a line is only ticked once that run
 * has actually completed. Before a run starts it shows what it is about to
 * do, never a fake transcript of work it has not done.
 */
export function AiAssistantPanel({ incident }: { incident: IncidentSummary | null }) {
  const navigate = useNavigate()
  const { status: healthStatus } = useHealth()
  const [question, setQuestion] = useState('')
  const explain = useExplain(incident?.id ?? 0)
  const online = healthStatus === 'healthy'

  function ask() {
    if (!incident) return
    const trimmed = question.trim()
    navigate(`/assistant?incident=${incident.id}`, trimmed ? { state: { prefillChatMessage: trimmed } } : undefined)
  }

  return (
    <Card
      title="AI security assistant"
      icon={<Sparkles className="h-3.5 w-3.5" />}
      accent="violet"
      className="border-accent-violet/25 bg-gradient-to-b from-accent-violet/8 to-transparent"
      action={
        <Badge accent={online ? 'violet' : 'neutral'} dot>
          {online ? 'AI online' : 'API offline'}
        </Badge>
      }
    >
      {!incident ? (
        <EmptyState
          icon={<Sparkles className="h-5 w-5" />}
          message="No open incident to analyse"
          hint="Ingest logs, then the assistant will pick the highest-severity open incident to work on."
        />
      ) : (
        <div className="flex flex-col gap-3">
          <div className="flex items-center justify-between gap-2 rounded-control border border-line bg-surface-2/40 px-3 py-2">
            <div className="min-w-0">
              <p className="truncate text-body text-text-dim">{incident.title}</p>
              <p className="truncate text-micro text-text-faint">
                {incidentRef(incident.id)} - {incident.host}
              </p>
            </div>
            <SeverityBadge severity={incident.severity} dot={false} />
          </div>

          <div className="rounded-control border border-accent-violet/20 bg-bg-deep/60 px-3 py-2.5 font-mono text-micro">
            {EXPLAIN_STAGES.map((stage, index) => {
              const done = explain.status === 'success' || (explain.status === 'loading' && index < explain.stageIndex)
              const running = explain.status === 'loading' && index === explain.stageIndex
              return (
                <p
                  key={stage}
                  className={clsx(
                    'flex items-center gap-1.5 py-0.5',
                    done ? 'text-accent-green' : running ? 'text-accent-violet' : 'text-text-faint',
                  )}
                >
                  <span className="text-text-faint">{'>'}</span>
                  <span className="truncate">{stage}</span>
                  {done && <Check className="h-3 w-3 shrink-0" />}
                  {running && <TypingDots className="shrink-0" />}
                </p>
              )
            })}
            <p className="mt-1 border-t border-line-soft pt-1.5 text-accent-cyan">
              {explain.status === 'success'
                ? 'AI status: analysis ready'
                : explain.status === 'loading'
                  ? 'AI status: working'
                  : explain.status === 'error'
                    ? `AI status: ${explain.error}`
                    : 'AI status: ready'}
            </p>
          </div>

          {explain.status === 'success' && explain.result && (
            <p className="line-clamp-3 text-meta text-text-muted">
              {explain.result.explanation.replace(/[#*`]/g, '').trim().slice(0, 260)}
            </p>
          )}

          <div className="flex items-center gap-2">
            <input
              value={question}
              onChange={(event) => setQuestion(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === 'Enter') ask()
              }}
              placeholder="Ask about this incident, threat or technique..."
              aria-label="Ask the AI assistant"
              className="h-9 w-full rounded-control border border-line bg-surface-2/50 px-3 text-meta text-text placeholder:text-text-faint focus:border-accent-violet/50 focus:outline-none"
            />
            <Button variant="icon" onClick={ask} aria-label="Send question">
              <SendHorizontal className="h-4 w-4" />
            </Button>
          </div>

          <div className="grid grid-cols-2 gap-2">
            <Button
              variant="secondary"
              onClick={explain.run}
              disabled={explain.status === 'loading' || !online}
              icon={<Sparkles className="h-3.5 w-3.5" />}
            >
              {explain.status === 'loading' ? 'Analysing' : 'Run AI analysis'}
            </Button>
            <Button
              variant="primary"
              onClick={() => navigate(`/assistant?incident=${incident.id}`)}
              icon={<MessageSquare className="h-3.5 w-3.5" />}
            >
              Open chat
            </Button>
          </div>
        </div>
      )}
    </Card>
  )
}
