"""Incident explanation generation: retrieve -> draft explanation -> self-critique.

Combines rag/retriever.py + rag/prompts.py + rag/llm_client.py into one
service function, per the roadmap's layering discipline (routes/callers use
this, not the individual rag/* modules directly). The self-critique pass is
a second LLM call that checks the draft against its own retrieved sources
and flags any claim the sources don't actually support, so callers get an
explanation that's already been checked rather than a raw ungrounded draft.

Takes a loose `incident: dict` (see rag/prompts.py's docstring for why) --
test against Pair 1's early alerts once available, or mocked incident data
until then (per roadmap Day 8 note).
"""

import logging
from dataclasses import dataclass

from langchain_core.prompts import ChatPromptTemplate

from app.rag.llm_client import generate
from app.rag.prompts import build_explanation_prompt
from app.rag.retriever import retrieve

logger = logging.getLogger(__name__)

DEFAULT_K = 5

CRITIQUE_SYSTEM_PROMPT = """You are a fact-checking reviewer for SOC incident explanations. You \
will be given a draft explanation and the exact source chunks it was supposed to be grounded in.

Check every factual claim in the draft against the sources:
- A claim is SUPPORTED if the sources directly state it or clearly imply it.
- A claim is NOT SUPPORTED if the sources don't mention it, or the draft goes further than what \
the sources actually say.

If every claim is supported, respond with exactly: No issues found.
Otherwise, respond with one line per unsupported or low-confidence claim, each starting with \
"- ", briefly stating the claim and why the sources don't support it. Do not repeat claims that \
are fine. Do not add any other commentary."""

CRITIQUE_HUMAN_PROMPT = """## Draft explanation
{draft}

## Source chunks it should be grounded in
{retrieved_context}

## Task
List any claims in the draft that are not supported by the source chunks above, following the \
system instructions."""

CRITIQUE_PROMPT = ChatPromptTemplate.from_messages(
    [
        ("system", CRITIQUE_SYSTEM_PROMPT),
        ("human", CRITIQUE_HUMAN_PROMPT),
    ]
)

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


def _self_critique(draft: str, chunks: list[dict]) -> str | None:
    """Ask the LLM to check its own draft against the retrieved chunks.

    Returns None if the draft's claims are all supported, otherwise the
    critique text listing the unsupported/low-confidence claims.
    """
    from app.rag.prompts import format_chunks

    messages = CRITIQUE_PROMPT.format_messages(
        draft=draft,
        retrieved_context=format_chunks(chunks),
    )
    critique = generate(messages).strip()

    if critique.lower().startswith(_NO_ISSUES):
        return None
    return critique


def generate_explanation(incident: dict, k: int = DEFAULT_K) -> ExplanationResult:
    """Retrieve context for `incident`, draft an explanation, then self-check
    the draft against the retrieved chunks before returning."""
    query = _build_retrieval_query(incident)
    technique_id = incident.get("technique_id")

    chunks = retrieve(query, k=k, technique_id=technique_id)
    logger.info("retrieved %d chunks for incident explanation (query=%r)", len(chunks), query)

    draft = generate(build_explanation_prompt(incident, chunks))

    critique = _self_critique(draft, chunks)
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
