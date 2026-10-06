"""Incident chat: retrieve -> answer, scoped to one incident + its prior chat turns (Day 11).

Mirrors explain_service.py's retrieve+prompt+LLM composition (Day 8's roadmap
layering discipline: routes/callers use this, not the individual rag/*
modules directly) but answers a free-form follow-up question instead of
producing a fixed 3-section explanation, and folds prior turns into the
prompt so the LLM can handle "what about the second one?"-style follow-ups.
No self-critique pass here (unlike explain_service) -- chat is a
conversational back-and-forth, not a one-shot report, so this stays to one
LLM call per turn.
"""

import logging
from dataclasses import dataclass

from app.rag.llm_client import generate
from app.rag.prompts import build_chat_prompt
from app.rag.retriever import retrieve
from app.rag.safety import annotate_unknown_technique_ids, technique_filter_ids

logger = logging.getLogger(__name__)

DEFAULT_K = 5


@dataclass
class ChatReplyResult:
    """Everything a caller (routes_chat.py, tests) might need."""

    reply: str  # the LLM's answer to the new message
    chunks: list[dict]  # the retrieved chunks used to ground the answer


def _build_retrieval_query(incident: dict, message: str) -> str:
    """Same incident-field query explain_service._build_retrieval_query
    uses, plus the user's new question -- so retrieval reflects what's
    actually being asked, not just the static incident summary."""
    parts = [
        incident.get("rule_name"),
        incident.get("technique_id"),
        incident.get("process"),
        incident.get("command_line"),
        incident.get("description"),
        message,
    ]
    query = " ".join(str(p) for p in parts if p)
    return query or "security incident"


def generate_chat_reply(incident: dict, history: list[dict], message: str, k: int = DEFAULT_K) -> ChatReplyResult:
    """Retrieve context for `message` (in the context of `incident`) and
    generate a grounded reply, given prior turns in `history` (each a dict
    with `role`/`content`, oldest first)."""
    query = _build_retrieval_query(incident, message)
    filter_ids = technique_filter_ids(incident.get("technique_ids") or [incident.get("technique_id")])

    chunks = retrieve(query, k=k, technique_ids=filter_ids or None)
    logger.info("retrieved %d chunks for incident chat (query=%r)", len(chunks), query)

    reply, unknown_ids = annotate_unknown_technique_ids(generate(build_chat_prompt(incident, chunks, history, message)))
    if unknown_ids:
        logger.warning("chat reply cited unknown technique id(s): %s", unknown_ids)

    return ChatReplyResult(reply=reply, chunks=chunks)


if __name__ == "__main__":
    sample_incident = {
        "host": "WIN10-ANALYST",
        "process": "powershell.exe",
        "command_line": "powershell.exe -enc SQBFAFgA...",
        "user": "jdoe",
        "technique_id": "T1059.001",
    }
    result = generate_chat_reply(sample_incident, history=[], message="Why was this flagged?")
    print("--- reply ---")
    print(result.reply)
    print(f"\n--- {len(result.chunks)} chunks used ---")
