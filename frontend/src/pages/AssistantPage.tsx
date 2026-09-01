import { ArrowRight, Bot, BookOpen, Clock, Gauge, MessagesSquare, Sparkles, Target } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom'
import { ChatHistory } from '../components/chat/ChatHistory'
import { CommandInput } from '../components/chat/CommandInput'
import { EvidenceSourcePanel } from '../components/incidents/EvidenceSourcePanel'
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorState,
  KeyValue,
  ListRow,
  PageHeader,
  Select,
  SeverityBadge,
  SeverityDotMarker,
  StatusBadge,
} from '../components/ui'
import { useHealth } from '../context/health/useHealth'
import { useIncidentsSnapshot } from '../context/incidents/useIncidentsSnapshot'
import { useExplain } from '../hooks/useExplain'
import { useIncidentChat } from '../hooks/useIncidentChat'
import { selectMostActionableIncident } from '../lib/aggregations'
import { formatDuration, formatRelativeTime, incidentRef } from '../lib/format'

const SUGGESTED_QUESTIONS = [
  'What happened in this incident, in plain language?',
  'What should I do first to contain it?',
  'Which MITRE techniques are involved and why?',
  'How can I tell whether this is a false positive?',
  'What evidence should I collect before remediating?',
  'How do I prevent this from happening again?',
]

/**
 * The full-page security copilot.
 *
 * Chat and explain are incident-scoped in NightOwl (POST
 * /incidents/{id}/chat and /explain) -- there is no general-purpose chat
 * endpoint -- so this page makes the incident under discussion explicit in
 * a context rail and lets the analyst switch it, rather than pretending to
 * be a free-floating chatbot that silently answers about nothing.
 */
function AssistantPage() {
  const navigate = useNavigate()
  const location = useLocation()
  const [searchParams, setSearchParams] = useSearchParams()
  const { incidents, loading, error } = useIncidentsSnapshot()
  const { status: healthStatus } = useHealth()

  const paramId = Number(searchParams.get('incident'))
  const fallback = selectMostActionableIncident(incidents) ?? incidents[0] ?? null
  const incident = incidents.find((item) => item.id === paramId) ?? fallback
  const incidentId = incident?.id ?? 0

  const chat = useIncidentChat(incidentId)
  const explain = useExplain(incidentId)
  const scrollRef = useRef<HTMLDivElement>(null)

  const [prefill] = useState(() => (location.state as { prefillChatMessage?: string } | null)?.prefillChatMessage)
  const autoSent = useRef(false)

  useEffect(() => {
    if (!prefill || autoSent.current || !incidentId) return
    autoSent.current = true
    chat.send(prefill)
    navigate(`${location.pathname}?${searchParams.toString()}`, { replace: true })
  }, [prefill, incidentId, chat, navigate, location.pathname, searchParams])

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: 'smooth' })
  }, [chat.turns.length, chat.sending])

  const recentConversations = useMemo(
    () => chat.turns.filter((turn) => turn.role === 'user').slice(-6).reverse(),
    [chat.turns],
  )

  if (loading) return <EmptyState className="py-24" message="Loading incidents" />
  if (error) return <ErrorState className="py-24" message={error} />

  if (!incident) {
    return (
      <div className="p-5">
        <Card>
          <EmptyState
            icon={<Bot className="h-5 w-5" />}
            message="The assistant needs an incident to reason about"
            hint="NightOwl grounds every answer in a specific incident and the MITRE knowledge base. Ingest logs or run Demo Mode first."
            action={
              <Button className="mt-2" variant="primary" onClick={() => navigate('/demo')}>
                Open Demo Mode
              </Button>
            }
          />
        </Card>
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-4 p-5">
      <PageHeader
        title="AI Security Assistant"
        subtitle="Grounded in this incident and the MITRE ATT&CK knowledge base"
        icon={<Sparkles className="h-5 w-5 text-accent-violet" />}
        actions={
          <Badge accent={healthStatus === 'healthy' ? 'violet' : 'neutral'} dot>
            {healthStatus === 'healthy' ? 'AI online' : 'API offline'}
          </Badge>
        }
      />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <div className="flex flex-col gap-4 xl:col-span-8">
          <Card
            title="Conversation"
            icon={<MessagesSquare className="h-3.5 w-3.5" />}
            accent="violet"
            action={
              <Select
                value={String(incident.id)}
                onChange={(value) => setSearchParams({ incident: value })}
                options={incidents.slice(0, 50).map((item) => ({
                  label: `${incidentRef(item.id)} - ${item.title}`,
                  value: String(item.id),
                }))}
                className="w-64"
              />
            }
          >
            {chat.error ? (
              <ErrorState message={chat.error} />
            ) : (
              <div ref={scrollRef} className="max-h-[46vh] min-h-[240px] overflow-y-auto pr-1">
                <ChatHistory turns={chat.turns} loading={chat.loading} sending={chat.sending} />
              </div>
            )}

            <div className="mt-3">
              <CommandInput
                onSubmit={chat.send}
                disabled={chat.sending}
                note={chat.sendError ?? 'AI responses may contain inaccuracies. Verify critical information.'}
              />
            </div>
          </Card>

          <Card title="Suggested questions" icon={<Sparkles className="h-3.5 w-3.5" />} accent="blue">
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              {SUGGESTED_QUESTIONS.map((question) => (
                <button
                  key={question}
                  type="button"
                  disabled={chat.sending}
                  onClick={() => chat.send(question)}
                  className="flex items-center justify-between gap-2 rounded-control border border-line bg-surface-2/40 px-3 py-2 text-left text-meta text-text-dim transition-colors hover:border-accent-violet/40 hover:text-text disabled:opacity-50"
                >
                  {question}
                  <ArrowRight className="h-3.5 w-3.5 shrink-0 text-accent-violet" />
                </button>
              ))}
            </div>
          </Card>
        </div>

        <div className="flex flex-col gap-4 xl:col-span-4">
          <Card
            title="Context"
            icon={<Target className="h-3.5 w-3.5" />}
            accent="blue"
            action={
              <Button size="sm" variant="ghost" onClick={() => navigate(`/incidents/${incident.id}`)}>
                View incident
              </Button>
            }
          >
            <div className="flex items-start justify-between gap-2">
              <div className="min-w-0">
                <p className="font-mono text-meta text-text-muted">{incidentRef(incident.id)}</p>
                <p className="truncate text-body text-text">{incident.title}</p>
              </div>
              <SeverityBadge severity={incident.severity} dot={false} />
            </div>
            <dl className="mt-3 grid grid-cols-2 gap-3">
              <KeyValue label="Host" value={incident.host} mono />
              <KeyValue label="Status" value={<StatusBadge status={incident.status} />} />
              <KeyValue label="Detected" value={formatRelativeTime(incident.created_at)} />
              <KeyValue label="Open for" value={formatDuration(incident.created_at)} mono />
            </dl>
          </Card>

          <Card
            title="AI insights"
            icon={<Gauge className="h-3.5 w-3.5" />}
            accent="violet"
            action={
              <Button size="sm" variant="secondary" onClick={explain.run} disabled={explain.status === 'loading'}>
                {explain.status === 'loading' ? 'Analysing' : 'Run analysis'}
              </Button>
            }
          >
            <div className="grid grid-cols-2 gap-2">
              <InsightTile icon={<Target className="h-4 w-4" />} value={incident.mitre_technique_ids[0] ?? '--'} label="Primary technique" />
              <InsightTile icon={<Gauge className="h-4 w-4" />} value={incident.severity.toUpperCase()} label="Engine severity" />
              <InsightTile icon={<BookOpen className="h-4 w-4" />} value={String(explain.result?.sources.length ?? 0)} label="Sources retrieved" />
              <InsightTile icon={<Clock className="h-4 w-4" />} value={formatDuration(incident.created_at)} label="Time open" />
            </div>
            <p className="mt-2 text-micro text-text-faint">
              Severity is assigned by the detection engine, not by the model; the assistant never invents a confidence
              score.
            </p>
          </Card>

          <Card title="Recent questions" icon={<MessagesSquare className="h-3.5 w-3.5" />} accent="neutral" bodyClassName="px-2 pb-3">
            {recentConversations.length === 0 ? (
              <EmptyState message="No questions asked yet" />
            ) : (
              <div className="flex flex-col">
                {recentConversations.map((turn) => (
                  <ListRow
                    key={turn.key}
                    marker={<SeverityDotMarker severity={incident.severity} />}
                    title={turn.content}
                    meta={turn.createdAt ? formatRelativeTime(turn.createdAt) : 'this session'}
                  />
                ))}
              </div>
            )}
          </Card>
        </div>
      </div>

      {/* Full-width, not the right rail: a real explanation can run to
          several hundred pixels, and a narrow xl:col-span-4 column made it
          tower over the left column, leaving the left side empty on scroll. */}
      <Card title="Sources and references" icon={<BookOpen className="h-3.5 w-3.5" />} accent="cyan">
        <EvidenceSourcePanel
          status={explain.status}
          result={explain.result}
          error={explain.error}
          selfCritiqueFlagged={explain.selfCritiqueFlagged}
        />
      </Card>
    </div>
  )
}

function InsightTile({ icon, value, label }: { icon: React.ReactNode; value: string; label: string }) {
  return (
    <div className="flex flex-col items-center gap-1 rounded-control border border-line bg-surface-2/40 px-2 py-3 text-center">
      <span className="text-accent-violet">{icon}</span>
      <span className="truncate font-mono text-title font-semibold text-text">{value}</span>
      <span className="text-micro text-text-faint">{label}</span>
    </div>
  )
}

export default AssistantPage
