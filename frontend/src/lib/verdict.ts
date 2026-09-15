/**
 * The exactly-three-verdict synthesis final_plan.md Phase 13 asks for
 * (pending.md item 5): NightOwl already has both signals this needs --
 * coverage honesty (`covered_events`/`uncovered_events`) and rule matches
 * -- but showed them as separate numbers instead of one synthesized
 * conclusion. "No malicious activity detected" is dishonest when a large
 * share of a file's events had no rule that could ever evaluate them;
 * the correct read is Inconclusive, not Clean.
 *
 * A fourth kind, `detected_with_uncovered`, was added once the backend
 * stopped suppressing the uncovered-events AI opinion whenever any rule
 * matched (routes_ingest.py's trigger used to require `rule_matches ===
 * 0`, proven live to leave 1,531 uncovered events with zero analysis
 * alongside 2 real matches on one real capture). A real detection still
 * means "detected" -- this kind never softens that -- but it now also
 * flags that other, unrelated events in the same file went unchecked, so
 * the analyst knows to look at the AI opinion below rather than assuming
 * the matched rule(s) explain the whole file.
 *
 * Deliberately does NOT take the AI second opinion's *content* as an
 * input (only whether uncovered events exist, a plain count already on
 * IngestResponse): that mechanism is advisory-only by design (see
 * ai_opinion_service.py, AiOpinionPanel.tsx) and must never be able to
 * promote an objectively under-covered ingest to a Clean verdict just
 * because the model's read of a sample happened to say "nothing unusual."
 */

export type VerdictKind = "detected" | "detected_with_uncovered" | "inconclusive" | "clean"

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
    if (outcome.uncovered_events > 0) {
      return {
        kind: "detected_with_uncovered",
        label: "Suspicious activity detected -- coverage incomplete",
        explanation:
          "One or more loaded detection rules matched real evidence in this file. " +
          `${outcome.uncovered_events.toLocaleString()} other event(s) had no rule that could evaluate them -- ` +
          "see the advisory analysis below for what those events contain.",
      }
    }
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
