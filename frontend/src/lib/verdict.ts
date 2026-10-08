/**
 * What an upload shows: one verdict per file, built from what the backend
 * measured (see backend/app/detection/coverage.py).
 *
 * Every event type in a file is CHECKED (a rule or sequence detector evaluates
 * it), ROUTINE (everyday activity -- credential-manager reads, process exits,
 * logoffs -- that needs no rule) or UNCHECKED (security-relevant, nothing
 * evaluates it). The verdict:
 *
 *   detected   -- a rule or detector matched real evidence. Never softened.
 *   review     -- no detection, but unchecked events or an advisory pattern
 *                 deserve a human look. Never "normal".
 *   clean      -- nothing matched and everything is checked or routine:
 *                 "Normal -- no threats detected".
 *   empty      -- no evaluable events were extracted.
 *
 * It deliberately does NOT take the AI second opinion's content as input: that
 * mechanism is advisory only and must not be able to promote a file to Normal
 * (or demote it) on its own. backend/scripts/upload_sweep.py mirrors this
 * function -- keep the two in sync.
 */

export type VerdictKind = 'detected' | 'detected_with_uncovered' | 'review' | 'clean' | 'empty'

export interface Verdict {
  kind: VerdictKind
  label: string
  explanation: string
}

export function computeVerdict(outcome: {
  rule_matches: number
  covered_events: number
  routine_events?: number
  uncovered_events: number
  advisory_hits?: number
}): Verdict {
  const routine = outcome.routine_events ?? 0
  const advisory = outcome.advisory_hits ?? 0
  const total = outcome.covered_events + routine + outcome.uncovered_events

  if (outcome.rule_matches > 0) {
    if (outcome.uncovered_events > 0) {
      return {
        kind: 'detected_with_uncovered',
        label: 'Suspicious activity detected',
        explanation:
          'One or more detection rules matched real evidence in this file. ' +
          `${outcome.uncovered_events.toLocaleString()} other security-relevant event(s) are not checked by any rule -- ` +
          'see the AI review below for what those contain.',
      }
    }
    return {
      kind: 'detected',
      label: 'Suspicious activity detected',
      explanation: 'One or more detection rules matched real evidence in this file.',
    }
  }

  if (total === 0) {
    return {
      kind: 'empty',
      label: 'No events found',
      explanation: 'No evaluable events were extracted from this file -- there is nothing here to judge.',
    }
  }

  if (outcome.uncovered_events > 0 || advisory > 0) {
    const parts: string[] = []
    if (outcome.uncovered_events > 0) {
      parts.push(`${outcome.uncovered_events.toLocaleString()} security-relevant event(s) that no rule checks`)
    }
    if (advisory > 0) {
      parts.push(`${advisory.toLocaleString()} event(s) matching a pattern that is too noisy for a rule`)
    }
    return {
      kind: 'review',
      label: 'Review recommended',
      explanation: `No detection rule matched, but the file contains ${parts.join(' and ')}.`,
    }
  }

  const checked = outcome.covered_events.toLocaleString()
  return {
    kind: 'clean',
    label: 'Normal -- no threats detected',
    explanation:
      `${checked} event(s) were checked against the detection rules and none matched` +
      (routine > 0
        ? `; ${routine.toLocaleString()} more are everyday activity (credential reads, process exits, service and power events) that needs no rule.`
        : '.'),
  }
}
