import { AlertTriangle, CheckCircle2, CircleDot, CopyCheck, HelpCircle, Info, Radar, ShieldCheck, XCircle } from 'lucide-react'
import { Link } from 'react-router-dom'
import type { EventIdCoverageGroup, IngestResponse } from '../../api'
import { eventTypeLabel } from '../../lib/events'
import { computeVerdict, type VerdictKind } from '../../lib/verdict'
import { Badge, Card, ListRow, MiniStat, type Accent } from '../ui'

const VERDICT_META: Record<VerdictKind, { accent: Accent; icon: typeof AlertTriangle }> = {
  detected: { accent: 'red', icon: AlertTriangle },
  // Same red/AlertTriangle as a plain detection -- a real match is still a
  // real match -- but this kind exists specifically so the pointer below
  // can tell the analyst other, unrelated events in the file weren't
  // checked at all.
  detected_with_uncovered: { accent: 'red', icon: AlertTriangle },
  review: { accent: 'amber', icon: HelpCircle },
  clean: { accent: 'green', icon: ShieldCheck },
  empty: { accent: 'neutral', icon: HelpCircle },
}

/**
 * Sysmon event-id labels only ever apply to a Sysmon-channel event -- raw
 * Windows event IDs are not unique across channels (see
 * detection/engine.py's CATEGORY_TO_EVENT_ID and the channel guard in
 * evaluate_event()), so a same-numbered Security-channel group must never
 * borrow Sysmon's vocabulary and instead falls back to the bare "Event
 * <id>" form.
 */
/** First few names plus a count, so a machine with 47 log providers does not
 *  turn one stat tile into a screen-high column. */
function summarizeList(items: string[], max: number): string {
  if (items.length <= max) return items.join(', ')
  return `${items.slice(0, max).join(', ')} and ${items.length - max} more`
}

function groupLabel(group: EventIdCoverageGroup): string {
  return eventTypeLabel(group.event_id, group.channel)
}

/**
 * The telemetry profiler (pending.md item 4): "before showing '0 alerts,'
 * show what's actually in the file." Renders for every upload, not only
 * ones with a real alert or an AI opinion -- a file that is 100% covered
 * and genuinely clean deserves this view just as much as one with gaps.
 * Every field here is a direct read of IngestResponse, computed by the
 * backend in the same ingest pass; this component does no analysis of
 * its own, only a view of one that already exists.
 *
 * Also carries the synthesized Detected/Inconclusive/Clean verdict
 * banner (pending.md item 5, see lib/verdict.ts) at the top -- the same
 * `computeVerdict()` call LogUploadControl.tsx's toast uses, so the two
 * never independently drift on which of the three categories an ingest
 * falls into.
 */
export function TelemetryProfilePanel({
  ingest,
  hasAiOpinion = false,
}: {
  ingest: IngestResponse | null
  /** Whether an AI second opinion was also triggered for this ingest --
   *  when the verdict below is Inconclusive, this adds a pointer to it as
   *  extra context. Never changes which verdict applies: the AI opinion
   *  is advisory-only and must never promote Inconclusive to Clean (see
   *  lib/verdict.ts). */
  hasAiOpinion?: boolean
}) {
  if (ingest === null) return null

  const totalClassified = ingest.covered_events + ingest.routine_events + ingest.uncovered_events
  const checkedPercent = totalClassified > 0 ? (ingest.covered_events / totalClassified) * 100 : null
  // A fully-duplicate re-upload (every record already matched a stored
  // event -- see event_service.find_existing_event_keys) never evaluated
  // anything new: computeVerdict() would otherwise read this as
  // "no evaluable events," which is misleading (there WERE events, they
  // were just already known) rather than "nothing new happened."
  const isFullyDuplicate = ingest.events_ingested === 0 && ingest.duplicate_events_skipped > 0
  const verdict = computeVerdict(ingest)
  const verdictMeta = VERDICT_META[verdict.kind]

  return (
    <Card
      title="Telemetry profile"
      subtitle={`What's actually in ${ingest.filename}`}
      icon={<Radar className="h-4 w-4" />}
      accent="primary"
    >
      <div className="flex flex-col gap-3">
        <div className="rounded-control border border-line bg-surface-2/40 px-3 py-2.5">
          {isFullyDuplicate ? (
            <>
              <Badge accent="neutral">
                <CopyCheck className="h-3 w-3" />
                Already ingested
              </Badge>
              <p className="mt-1.5 text-meta text-text-dim">
                All {ingest.duplicate_events_skipped.toLocaleString()} event(s) in this file were already stored --
                nothing new to evaluate.
              </p>
            </>
          ) : (
            <>
              <Badge accent={verdictMeta.accent}>
                <verdictMeta.icon className="h-3 w-3" />
                {verdict.label}
              </Badge>
              <p className="mt-1.5 text-meta text-text-dim">{verdict.explanation}</p>
              {(verdict.kind === 'review' || verdict.kind === 'detected_with_uncovered') && hasAiOpinion && (
                <p className="mt-1 text-micro text-text-faint">
                  An AI review of the events no rule checks is below -- advisory context, not a verdict of its own.
                </p>
              )}
              {ingest.notices.map((notice) => (
                <p key={notice.message} className="mt-1.5 flex items-start gap-1.5 text-meta text-text-dim">
                  <Info className="mt-0.5 h-3.5 w-3.5 shrink-0 text-accent-primary" />
                  <span>
                    <span className="font-medium text-text">Note:</span> {notice.message}. Shown for information; it does
                    not change the verdict.
                  </span>
                </p>
              ))}
              {ingest.ml_mode !== 'off' && ingest.ml_anomalies > 0 && (
                <p className="mt-1.5 text-meta text-text-dim">
                  <span className="font-medium text-text">ML check (experimental):</span> {ingest.ml_anomalies} unusual
                  window(s) of activity recorded as supporting evidence, not detections.{' '}
                  <Link to="/alerts?view=ml" className="text-accent-primary underline-offset-2 hover:underline">
                    Open the ML view
                  </Link>
                </p>
              )}
            </>
          )}
        </div>

        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          <MiniStat
            label="Channels"
            value={ingest.channels.length}
            note={ingest.channels.join(', ') || 'None recognized'}
          />
          <MiniStat
            label="Providers"
            value={ingest.providers.length}
            note={summarizeList(ingest.providers, 6) || 'None recorded'}
          />
          <MiniStat label="Event types" value={ingest.event_id_breakdown.length} />
          <MiniStat
            label="Checked by a rule"
            value={checkedPercent === null ? '--' : `${checkedPercent.toFixed(0)}%`}
            note={`${ingest.routine_events.toLocaleString()} everyday · ${ingest.uncovered_events.toLocaleString()} unchecked`}
          />
        </div>

        <ul className="flex flex-col gap-0.5">
          {ingest.event_id_breakdown.map((group) => (
            <ListRow
              key={`${group.channel ?? 'unknown'}-${group.event_id}`}
              marker={
                group.kind === 'routine' ? (
                  <CircleDot className="h-3.5 w-3.5 text-text-faint" />
                ) : group.covered ? (
                  <CheckCircle2 className="h-3.5 w-3.5 text-accent-green" />
                ) : (
                  <XCircle className="h-3.5 w-3.5 text-accent-amber" />
                )
              }
              title={groupLabel(group)}
              meta={`${group.channel ?? 'Unrecognized channel'} · ${group.kind === 'routine' ? 'everyday, no rule needed' : group.covered ? 'checked' : 'not checked'}`}
              trailing={<span className="font-mono text-meta text-text-muted tabular-nums">{group.count}</span>}
            />
          ))}
          {ingest.event_id_breakdown.length === 0 && (
            <li className="px-2.5 py-2 text-meta text-text-muted">No events were ingested from this file.</li>
          )}
        </ul>
      </div>
    </Card>
  )
}
