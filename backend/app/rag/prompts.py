"""Prompt templates: incident context + retrieved KB chunks -> LLM prompt.

Deliberately takes a loose `incident: dict` rather than the (still-unpopulated)
Incident ORM model, so this works today against mocked/sample incident data
and later against a real Incident-derived dict without this module changing
(see roadmap Day 8/9). `chunks` is exactly retriever.retrieve()'s return shape
(list of {chunk_id, document, metadata, score}), so explain_service.py (Day 8)
can pipe retrieval straight into this with no glue code.

Day 11 adds a second template, `build_chat_prompt`, for incident chat -- same
`format_incident_context`/`format_chunks` helpers, plus prior turns rendered
via `format_chat_history` so the LLM can resolve conversational follow-ups.
"""

from langchain_core.messages import BaseMessage
from langchain_core.prompts import ChatPromptTemplate

SYSTEM_PROMPT = """You are NightOwl, an experienced SOC (Security Operations Center) analyst \
explaining a detected security incident to a junior analyst who is still learning. Your job is \
to translate raw telemetry and MITRE ATT&CK context into a clear, plain-English explanation of \
what likely happened and why it was flagged.

Rules you must follow:
1. Base your explanation ONLY on the incident details and the retrieved context chunks provided \
below. Do not invent facts, hosts, users, IPs, or techniques that are not present in the input.
2. If the retrieved context does not clearly support a claim, say so explicitly instead of \
guessing (e.g. "the retrieved context does not specify ...").
3. Reference MITRE ATT&CK technique IDs (e.g. T1059.001) when the retrieved context supplies \
them, and briefly explain what that technique means in this context.
4. Write for a junior analyst: define jargon briefly, keep sentences short, and prefer concrete \
detail (process names, command lines, hosts) over vague generalities.
5. Structure your answer in three short sections, each with a markdown heading using EXACTLY \
this text (needed so callers can split the response programmatically):
   - "## What happened": a 2-4 sentence plain-English summary of the observed activity.
   - "## Why it matters": the ATT&CK technique(s) involved and the attacker goal they usually serve.
   - "## Recommended next steps": 2-4 concrete triage/response actions, grounded in the retrieved \
playbook context if present, or general SOC best practice if not.
6. Keep the whole response under ~300 words. Do not repeat the raw input back verbatim."""

HUMAN_PROMPT = """## Incident context
{incident_context}

## Retrieved knowledge base context
{retrieved_context}

## Task
Using only the information above, explain this incident to a junior analyst by following the \
system instructions."""

EXPLANATION_PROMPT = ChatPromptTemplate.from_messages(
    [
        ("system", SYSTEM_PROMPT),
        ("human", HUMAN_PROMPT),
    ]
)


def format_incident_context(incident: dict) -> str:
    """Render an incident dict as a readable bullet list for the prompt."""
    if not incident:
        return "(no incident context provided)"
    lines = [f"- {key}: {value}" for key, value in incident.items() if value not in (None, "", [])]
    return "\n".join(lines) if lines else "(no incident context provided)"


def format_chunks(chunks: list[dict]) -> str:
    """Render retriever.retrieve()'s output as numbered, citable context blocks."""
    if not chunks:
        return "(no relevant knowledge base context retrieved)"
    blocks = []
    for i, chunk in enumerate(chunks, start=1):
        metadata = chunk.get("metadata", {})
        source_bits = ", ".join(f"{k}={v}" for k, v in metadata.items() if v)
        blocks.append(
            f"[{i}] (score={chunk.get('score', 0):.3f}, {source_bits})\n{chunk.get('document', '')}"
        )
    return "\n\n".join(blocks)


def build_explanation_prompt(incident: dict, chunks: list[dict]) -> list[BaseMessage]:
    """Render the full system+human message pair ready for llm_client.generate()."""
    return EXPLANATION_PROMPT.format_messages(
        incident_context=format_incident_context(incident),
        retrieved_context=format_chunks(chunks),
    )


CHAT_SYSTEM_PROMPT = """You are NightOwl, an experienced SOC (Security Operations Center) analyst \
answering a junior analyst's follow-up questions about ONE specific security incident, in an \
ongoing chat conversation.

Rules you must follow:
1. Base your answer ONLY on the incident details, the retrieved context chunks, and the prior \
conversation turns provided below. Do not invent facts, hosts, users, IPs, or techniques that are \
not present in the input.
2. If the retrieved context does not clearly support a claim, say so explicitly instead of \
guessing (e.g. "the retrieved context does not specify ...").
3. Reference MITRE ATT&CK technique IDs (e.g. T1059.001) when the retrieved context supplies \
them.
4. Write for a junior analyst: define jargon briefly, keep sentences short.
5. Use the prior conversation turns to resolve follow-up references (e.g. "what about the second \
one?" refers back to something mentioned earlier in the chat).
6. Answer conversationally -- a few sentences is usually enough. Only use a list or headings if \
the question specifically calls for step-by-step instructions. Keep the response under ~200 words \
unless the question specifically asks for more detail."""

CHAT_HUMAN_PROMPT = """## Incident context
{incident_context}

## Retrieved knowledge base context
{retrieved_context}

## Conversation so far
{chat_history}

## New question
{message}

## Task
Answer the new question using only the information above, following the system instructions."""

CHAT_PROMPT = ChatPromptTemplate.from_messages(
    [
        ("system", CHAT_SYSTEM_PROMPT),
        ("human", CHAT_HUMAN_PROMPT),
    ]
)


def format_chat_history(history: list[dict]) -> str:
    """Render prior chat turns (each {"role": ..., "content": ...}, oldest
    first) as plain "role: content" lines for the prompt."""
    if not history:
        return "(no prior messages -- this is the first question)"
    return "\n".join(f"{turn['role']}: {turn['content']}" for turn in history)


def build_chat_prompt(incident: dict, chunks: list[dict], history: list[dict], message: str) -> list[BaseMessage]:
    """Render the full system+human message pair ready for llm_client.generate()."""
    return CHAT_PROMPT.format_messages(
        incident_context=format_incident_context(incident),
        retrieved_context=format_chunks(chunks),
        chat_history=format_chat_history(history),
        message=message,
    )


RECOMMENDED_STEPS_HEADING = "## Recommended next steps"


def extract_recommended_response(explanation: str) -> str:
    """Pull the "## Recommended next steps" section out of a generated
    explanation (Day 9: exposed as its own field on the explain endpoint's
    response, alongside the full explanation).

    Returns "" if the heading isn't present -- e.g. the LLM didn't follow the
    requested format, or `explanation` is the empty string -- rather than
    raising, since the full explanation text is still returned either way.
    """
    idx = explanation.find(RECOMMENDED_STEPS_HEADING)
    if idx == -1:
        return ""
    return explanation[idx + len(RECOMMENDED_STEPS_HEADING):].strip()


if __name__ == "__main__":
    sample_incident = {
        "host": "WIN10-ANALYST",
        "process": "powershell.exe",
        "command_line": "powershell.exe -enc SQBFAFgA...",
        "user": "jdoe",
    }
    sample_chunks = [
        {
            "chunk_id": "T1059.001-mitre-0",
            "document": "Adversaries may abuse PowerShell commands and scripts for execution.",
            "metadata": {"technique_id": "T1059.001", "technique_name": "PowerShell", "tactics": "execution"},
            "score": 0.8123,
        }
    ]
    for message in build_explanation_prompt(sample_incident, sample_chunks):
        print(f"--- {message.type} ---")
        print(message.content)
