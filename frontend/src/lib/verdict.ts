/**
 * The exactly-three-verdict synthesis final_plan.md Phase 13 asks for
 * (pending.md item 5): NightOwl already has both signals this needs --
 * coverage honesty (`covered_events`/`uncovered_events`) and rule matches
 * -- but showed them as separate numbers instead of one synthesized
 * conclusion. "No malicious activity detected" is dishonest when a large
 * share of a file's events had no rule that could ever evaluate them;
 * the correct read is Inconclusive, not Clean.
 *
 * Deliberately does NOT take the AI second opinion as an input: that
 * mechanism is advisory-only by design (see ai_opinion_service.py,
 * AiOpinionPanel.tsx) and must never be able to promote an objectively
 * under-covered ingest to a Clean verdict just because the model's read
 * of a sample happened to say "nothing unusual." Callers that have an AI
 * opinion available may show it as extra context alongside an
 * Inconclusive verdict, never as an input to which verdict applies.
 */

export type VerdictKind = "detected" | "inconclusive" | "clean"

export interface Verdict {
  kind: VerdictKind
  label: string
  explanation: string
}

export function computeVerdict(outcome: {
  rule_matches: number
  covered_events: number
  uncovered_events: number
}): Verdict {
  if (outcome.rule_matches > 0) {
    return {
      kind: "detected",
      label: "Suspicious activity detected",
      explanation: "One or more loaded detection rules matched real evidence in this file.",
    }
  }

  const totalClassified = outcome.covered_events + outcome.uncovered_events
  if (totalClassified === 0) {
    return {
      kind: "inconclusive",
      label: "Inconclusive",
      explanation: "No evaluable events were extracted from this file -- there is nothing here to rule anything out from.",
    }
  }

  if (outcome.uncovered_events > 0) {
    return {
      kind: "inconclusive",
      label: "Inconclusive",
      explanation:
        `${outcome.uncovered_events.toLocaleString()} of ${totalClassified.toLocaleString()} events had no loaded ` +
        "rule that could ever evaluate them -- available detection coverage was insufficient to rule out malicious activity.",
    }
  }

  return {
    kind: "clean",
    label: "No known malicious activity observed",
    explanation: `Every one of ${totalClassified.toLocaleString()} events was evaluated against the loaded rules and none matched.`,
  }
}
