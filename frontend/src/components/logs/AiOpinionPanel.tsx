import { AlertTriangle, HelpCircle, ShieldCheck, Sparkles } from 'lucide-react'
import type { AiOpinionAssessment } from '../../api'
import { useAiOpinion } from '../../hooks/useAiOpinion'
import { AIThinking, Badge, Button, Card, EmptyState, Markdown, type Accent } from '../ui'

const ASSESSMENT_META: Record<AiOpinionAssessment, { label: string; accent: Accent; icon: typeof AlertTriangle }> = {
  worth_reviewing: { label: 'Worth reviewing', accent: 'amber', icon: AlertTriangle },
  nothing_unusual: { label: 'Nothing unusual in the events reviewed', accent: 'primary', icon: ShieldCheck },
  uncertain: { label: 'Uncertain', accent: 'neutral', icon: HelpCircle },
}

/**
 * `summary` is the model's entire raw response, including the trailing
 * "## Assessment: ..." and "## Limitations" headings the prompt requires
 * (rag/prompts.py) -- those are parsed into `assessment_label`/
 * `limitations` separately and rendered as their own elements below, so
 * showing them again verbatim inside the free-text body would just be
 * raw markdown leaking into a plain-text paragraph. This mirrors how the
 * backend's own `_extract_section` finds a heading boundary: the first
 * "\n## " marks where the structured tail begins.
 */
function stripTrailingHeadings(summary: string): string {
  return summary.split(/\n## /)[0]?.trim() ?? summary.trim()
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
  hasDetections = false,
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
  /** The file also has rule detections: this opinion reviews the other events only. */
  hasDetections?: boolean
}) {
  const { opinion, error, stalled, retry } = useAiOpinion(opinionId)

  if (opinionId === null) return null

  const assessment = opinion?.assessment_label ? ASSESSMENT_META[opinion.assessment_label] : null
  const subtitle =
    hasUncoveredEvents ?? true
      ? hasDetections
        ? 'Not a detection — the rule detections are listed above; this AI reads only the other events no rule checks'
        : 'Not a detection — an AI reading of the security-relevant events no rule checks'
      : 'Not a detection — an AI second look at a narrow pattern worth reviewing'
  const thinkingLabel = hasUncoveredEvents ?? true ? 'Reviewing events no rule checks' : 'Reviewing flagged pattern'

  // A response that never reached a terminal status (still "pending" or
  // absent) but the poll gave up anyway -- see useAiOpinion's `stalled`
  // docstring for the two cases this covers. Checked before the pending
  // branch below so a stuck poll doesn't spin forever.
  const isStalled = stalled && (!opinion || opinion.status === 'pending')

  return (
    <Card title="AI review of unchecked events" subtitle={subtitle} icon={<Sparkles className="h-4 w-4" />} accent="violet">
      {isStalled ? (
        <EmptyState
          message="AI opinion timed out"
          hint={error ?? 'No response after several attempts -- the model call may still finish; check back later.'}
          icon={<HelpCircle className="h-5 w-5" />}
        />
      ) : !opinion || opinion.status === 'pending' ? (
        <AIThinking label={thinkingLabel} />
      ) : opinion.status === 'failed' ? (
        <EmptyState
          message="AI opinion unavailable"
          hint={opinion.error ?? error ?? 'The model call failed.'}
          icon={<HelpCircle className="h-5 w-5" />}
          action={
            <Button variant="secondary" size="sm" onClick={retry}>
              Retry
            </Button>
          }
        />
      ) : (
        <div className="flex flex-col gap-3">
          {assessment && (
            <Badge accent={assessment.accent}>
              <assessment.icon className="h-3 w-3" />
              {assessment.label}
            </Badge>
          )}
          {opinion.summary && <Markdown content={stripTrailingHeadings(opinion.summary)} />}
          {opinion.attack_candidate_ids && opinion.attack_candidate_ids.length > 0 && (
            <div className="flex flex-col gap-1.5">
              <span className="text-micro font-medium uppercase tracking-wide text-text-faint">
                ATT&CK candidates (from retrieved reference material, not a detection)
              </span>
              <div className="flex flex-wrap gap-1.5">
                {opinion.attack_candidate_ids.map((id) => (
                  <Badge key={id} accent="violet">
                    {id}
                  </Badge>
                ))}
              </div>
            </div>
          )}
          {opinion.limitations && (
            <div className="rounded-control border border-line bg-surface-2/40 px-3 py-2">
              <span className="text-micro font-medium uppercase tracking-wide text-text-faint">Limitations</span>
              <Markdown content={opinion.limitations} className="mt-1" />
            </div>
          )}
        </div>
      )}
    </Card>
  )
}
