import { AlertTriangle, HelpCircle, ShieldCheck, Sparkles } from 'lucide-react'
import type { AiOpinionAssessment } from '../../api'
import { useAiOpinion } from '../../hooks/useAiOpinion'
import { AIThinking, Badge, Card, EmptyState, type Accent } from '../ui'

const ASSESSMENT_META: Record<AiOpinionAssessment, { label: string; accent: Accent; icon: typeof AlertTriangle }> = {
  worth_reviewing: { label: 'Worth reviewing', accent: 'amber', icon: AlertTriangle },
  nothing_unusual: { label: 'Nothing unusual noted', accent: 'primary', icon: ShieldCheck },
  uncertain: { label: 'Uncertain', accent: 'neutral', icon: HelpCircle },
}

/**
 * A deliberately separate visual language from every real-detection
 * surface on this page: its own `violet` accent (the app's fixed AI/RAG
 * channel, never reused for a real Alert/Incident), its own icon, and a
 * permanent subtitle stating what it is not. Never reuses the toast
 * tones ('warning'/'success'/'error') LogUploadControl reserves for real
 * detections -- see useAiOpinion.ts and ai_opinion_service.py for the
 * rest of that boundary.
 */
export function AiOpinionPanel({
  opinionId,
  hasUncoveredEvents,
}: {
  opinionId: number | null
  /** Whether this ingest actually had events no loaded rule could ever
   *  evaluate (IngestResponse.uncovered_events > 0). An opinion can also
   *  fire purely from a narrow advisory pattern (advisory_patterns.py) on
   *  a file that's 100% covered -- found live during the 39-file visual QA
   *  pass (2026-09-05): the old unconditional "no rule could evaluate"
   *  copy was flatly wrong on a file every event of which a loaded rule
   *  had genuinely evaluated. Defaults to true so a caller that hasn't
   *  been updated to pass this keeps today's copy rather than silently
   *  showing the wrong one. */
  hasUncoveredEvents?: boolean
}) {
  const { opinion, error } = useAiOpinion(opinionId)

  if (opinionId === null) return null

  const assessment = opinion?.assessment_label ? ASSESSMENT_META[opinion.assessment_label] : null
  const subtitle =
    hasUncoveredEvents ?? true
      ? 'Not a verified detection — an AI reading of events no rule could evaluate'
      : 'Not a verified detection — an AI second look at a narrow pattern worth reviewing'
  const thinkingLabel = hasUncoveredEvents ?? true ? 'Reviewing uncovered events' : 'Reviewing flagged pattern'

  return (
    <Card title="AI second opinion" subtitle={subtitle} icon={<Sparkles className="h-4 w-4" />} accent="violet">
      {!opinion || opinion.status === 'pending' ? (
        <AIThinking label={thinkingLabel} />
      ) : opinion.status === 'failed' ? (
        <EmptyState
          message="AI opinion unavailable"
          hint={opinion.error ?? error ?? 'The model call failed.'}
          icon={<HelpCircle className="h-5 w-5" />}
        />
      ) : (
        <div className="flex flex-col gap-3">
          {assessment && (
            <Badge accent={assessment.accent}>
              <assessment.icon className="h-3 w-3" />
              {assessment.label}
            </Badge>
          )}
          <p className="whitespace-pre-wrap text-meta text-text-dim">{opinion.summary}</p>
        </div>
      )}
    </Card>
  )
}
