"""Incident explanation generation: retrieve -> draft explanation -> self-critique.

Combines rag/retriever.py + rag/prompts.py + rag/llm_client.py into one
service function, per the roadmap's layering discipline (routes/callers use
this, not the individual rag/* modules directly). The self-critique pass is
a second LLM call that checks the draft against its own retrieved sources
(and, since Day 12, the incident context itself -- see
rag/prompts.py's build_critique_prompt docstring for why) and flags any
claim they don't actually support, so callers get an explanation that's
already been checked rather than a raw ungrounded draft.

Takes a loose `incident: dict` (see rag/prompts.py's docstring for why) --
test against Pair 1's early alerts once available, or mocked incident data
until then (per roadmap Day 8 note).
"""

import logging
from dataclasses import dataclass

from app.rag.llm_client import generate
from app.rag.prompts import build_critique_prompt, build_explanation_prompt
from app.rag.retriever import retrieve
from app.rag.safety import annotate_unknown_technique_ids, technique_filter_ids

logger = logging.getLogger(__name__)

DEFAULT_K = 5

_NO_ISSUES = "no issues found"


@dataclass
class ExplanationResult:
    """Everything a caller (Day 9's endpoint, chat, tests) might need."""

    explanation: str  # draft, with a "Confidence check" section appended if critique found issues
    draft: str  # the LLM's first-pass explanation, before self-critique
    critique: str | None  # None if the self-critique pass found no unsupported claims
    chunks: list[dict]  # the retrieved chunks used to ground both the draft and the critique


def _build_retrieval_query(incident: dict) -> str:
    """Turn incident fields into a free-text query for retriever.retrieve().

    No real Incident/Alert model is populated yet, so this pulls from
    whatever descriptive fields happen to be present rather than assuming a
    fixed schema -- keeps this working against both mocked incident dicts
    today and Pair 1's real alerts once Day 10 wires them up.
    """
    parts = [
        incident.get("rule_name"),
        incident.get("technique_id"),
        incident.get("process"),
        incident.get("command_line"),
        incident.get("description"),
    ]
    query = " ".join(str(p) for p in parts if p)
    return query or "security incident"


def _self_critique(draft: str, chunks: list[dict], incident: dict) -> str | None:
    """Ask the LLM to check its own draft against the incident context and
    the retrieved chunks.

    Returns None if the draft's claims are all supported, otherwise the
    critique text listing the unsupported/low-confidence claims.
    """
    critique = generate(build_critique_prompt(draft, chunks, incident)).strip()

    # Tolerate markdown decoration around the sentinel ("**No issues found.**").
    if critique.strip("*_` \n").lower().startswith(_NO_ISSUES):
        return None
    return critique


def generate_explanation(incident: dict, k: int = DEFAULT_K) -> ExplanationResult:
    """Retrieve context for `incident`, draft an explanation, then self-check
    the draft against the retrieved chunks before returning."""
    query = _build_retrieval_query(incident)
    # Every technique on the incident plus each one's parent: playbooks are
    # written against parent techniques (T1003) while rules emit
    # sub-techniques (T1003.001), so an exact first-technique filter never
    # retrieved them.
    filter_ids = technique_filter_ids(incident.get("technique_ids") or [incident.get("technique_id")])

    chunks = retrieve(query, k=k, technique_ids=filter_ids or None)
    logger.info("retrieved %d chunks for incident explanation (query=%r)", len(chunks), query)

    draft, unknown_ids = annotate_unknown_technique_ids(generate(build_explanation_prompt(incident, chunks)))
    if unknown_ids:
        logger.warning("explanation cited unknown technique id(s): %s", unknown_ids)

    critique = _self_critique(draft, chunks, incident)
    if critique:
        logger.info("self-critique flagged low-confidence claims: %s", critique)
        explanation = f"{draft}\n\n**Confidence check:**\n{critique}"
    else:
        explanation = draft

    return ExplanationResult(explanation=explanation, draft=draft, critique=critique, chunks=chunks)


if __name__ == "__main__":
    sample_incident = {
        "host": "WIN10-ANALYST",
        "process": "powershell.exe",
        "command_line": "powershell.exe -enc SQBFAFgA...",
        "user": "jdoe",
        "technique_id": "T1059.001",
    }
    result = generate_explanation(sample_incident)
    print("--- explanation ---")
    print(result.explanation)
    print(f"\n--- {len(result.chunks)} chunks used, critique flagged issues: {result.critique is not None} ---")
