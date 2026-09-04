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
export function AiOpinionPanel({ opinionId }: { opinionId: number | null }) {
  const { opinion, error } = useAiOpinion(opinionId)

  if (opinionId === null) return null

  const assessment = opinion?.assessment_label ? ASSESSMENT_META[opinion.assessment_label] : null

  return (
    <Card
      title="AI second opinion"
      subtitle="Not a verified detection — an AI reading of events no rule could evaluate"
      icon={<Sparkles className="h-4 w-4" />}
      accent="violet"
    >
      {!opinion || opinion.status === 'pending' ? (
        <AIThinking label="Reviewing uncovered events" />
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
