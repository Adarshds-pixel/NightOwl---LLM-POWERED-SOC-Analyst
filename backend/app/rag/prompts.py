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

Day 12 moves the self-critique prompt (`build_critique_prompt`) here from
explain_service.py, so all three templates live behind the same
`build_*_prompt` convention, and rewrites both it and the two generation
system prompts to fix two Day 10 hallucination-spot-check findings
(docs/research/hallucination-eval.md): critique used to flag the incident's
own context fields (e.g. `host`) as unsupported simply because it never saw
incident context, only retrieved chunks (finding #1); and a retrieved
chunk's *general* technique background (e.g. a playbook's example flag) was
stated by the generator as an *observed fact about this specific incident*
without the self-critique pass catching it (finding #2, spot-check #2's
`-enc` flag that the crafted incident never had).
"""

from langchain_core.messages import BaseMessage
from langchain_core.prompts import ChatPromptTemplate

from app.rag.safety import (
    LARGE_FIELD_LIMIT,
    UNTRUSTED_EVIDENCE_RULE,
    extract_strict_heading_label,
    fence,
    untrusted,
)

SYSTEM_PROMPT = """You are NightOwl, an experienced SOC (Security Operations Center) analyst \
explaining a detected security incident to a junior analyst who is still learning. Your job is \
to translate raw telemetry and MITRE ATT&CK context into a clear, plain-English explanation of \
what likely happened and why it was flagged.

Rules you must follow:
1. Base your explanation ONLY on the incident details and the retrieved context chunks provided \
below. Do not invent facts, hosts, users, IPs, or techniques that are not present in the input.
2. The retrieved context chunks describe the technique in GENERAL (typical flags, tools, commands, \
file paths a threat actor might use) -- this is background, not evidence about this specific \
incident. Only state that a specific flag, parameter, encoded value, tool, or file was used IN \
THIS INCIDENT if it literally appears in the incident details above. If a chunk mentions a detail \
the incident details don't confirm, phrase it as what the technique commonly involves in general \
(e.g. "this technique commonly uses an encoded `-enc` flag"), never as something this incident's \
command line showed.
3. If the retrieved context does not clearly support a claim, say so explicitly instead of \
guessing (e.g. "the retrieved context does not specify ...").
4. Reference MITRE ATT&CK technique IDs (e.g. T1059.001) when the retrieved context supplies \
them, and briefly explain what that technique means in this context.
5. Write for a junior analyst: define jargon briefly, keep sentences short, and prefer concrete \
detail (process names, command lines, hosts) over vague generalities.
6. Structure your answer in four short sections, each with a markdown heading using EXACTLY \
this text (needed so callers can split the response programmatically):
   - "## What happened": a 2-4 sentence plain-English summary of the observed activity.
   - "## Why it matters": the ATT&CK technique(s) involved and the attacker goal they usually serve.
   - "## Recommended next steps": 2-4 concrete triage/response actions, grounded in the retrieved \
playbook context if present, or general SOC best practice if not.
   - "## Confidence breakdown": exactly three labeled bullets, every one of which must be present \
even if its content is "None for this incident":
     - "- Fact:" claims taken directly from the incident context above (process, command line, \
host, user, matched rule, related events) -- things this specific incident's own data confirms.
     - "- Inference:" reasonable interpretation drawn from the retrieved technique background \
applied to this incident, not directly confirmed by the incident context itself.
     - "- Uncertainty:" anything the incident context and retrieved chunks together don't clearly \
establish, including cases where the evidence is thin (e.g. an incident with no related events, or \
a technique with only general background retrieved).
7. Keep the whole response under ~350 words. Do not repeat the raw input back verbatim.
8. """ + UNTRUSTED_EVIDENCE_RULE

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


_LARGE_FIELDS = {"command_line", "event_data", "related_events", "ScriptBlockText"}


def _render_value(key: str, value) -> str:
    limit = LARGE_FIELD_LIMIT if key in _LARGE_FIELDS else 1000
    if isinstance(value, list):
        return "\n".join(f"    - {untrusted(item, limit)}" for item in value)
    return untrusted(value, limit)


def format_incident_context(incident: dict) -> str:
    """Render an incident dict as a bullet list, fenced as untrusted evidence
    (host names, command lines, users and related events all come from logs
    an attacker can write to -- see rag/safety.py)."""
    if not incident:
        return "(no incident context provided)"
    lines = []
    for key, value in incident.items():
        if value in (None, "", []):
            continue
        rendered = _render_value(key, value)
        lines.append(f"- {key}:\n{rendered}" if isinstance(value, list) else f"- {key}: {rendered}")
    return fence("\n".join(lines)) if lines else "(no incident context provided)"


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
2. The retrieved context chunks describe the technique in GENERAL (typical flags, tools, commands, \
file paths a threat actor might use) -- this is background, not evidence about this specific \
incident. Only state that a specific flag, parameter, encoded value, tool, or file was used IN \
THIS INCIDENT if it literally appears in the incident details above; otherwise phrase it as what \
the technique commonly involves in general, never as something this incident showed.
3. If the retrieved context does not clearly support a claim, say so explicitly instead of \
guessing (e.g. "the retrieved context does not specify ...").
4. Reference MITRE ATT&CK technique IDs (e.g. T1059.001) when the retrieved context supplies \
them.
5. Write for a junior analyst: define jargon briefly, keep sentences short.
6. Use the prior conversation turns to resolve follow-up references (e.g. "what about the second \
one?" refers back to something mentioned earlier in the chat).
7. Answer conversationally -- a few sentences is usually enough. Only use a list or headings if \
the question specifically calls for step-by-step instructions. Keep the response under ~200 words \
unless the question specifically asks for more detail.
8. """ + UNTRUSTED_EVIDENCE_RULE

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


# Bound on how much prior conversation is ever sent to the LLM or folded
# into the chat cache key (see rag/cache.py) -- both must agree on the same
# definition of "recent enough to matter", so this one constant/function is
# the single source of truth for both. `list_messages()` (services/
# chat_service.py) is deliberately left unbounded itself: it's also used by
# the GET /chat history-listing endpoint, which should keep showing the
# full conversation to the analyst even once the LLM only sees the tail of
# it. A simple deterministic recency window (most recent N messages) is
# used rather than a token-aware or summarization-based bound -- keeps
# prompt growth bounded without an elaborate memory subsystem.
MAX_CHAT_HISTORY_MESSAGES = 10


def bound_chat_history(history: list[dict]) -> list[dict]:
    """Keep only the most recent MAX_CHAT_HISTORY_MESSAGES turns (history is
    oldest-first, so this is a plain tail slice, not a head slice)."""
    if len(history) <= MAX_CHAT_HISTORY_MESSAGES:
        return history
    return history[-MAX_CHAT_HISTORY_MESSAGES:]


def format_chat_history(history: list[dict]) -> str:
    """Render prior chat turns (each {"role": ..., "content": ...}, oldest
    first) as plain "role: content" lines for the prompt. Bounded to the
    most recent MAX_CHAT_HISTORY_MESSAGES turns (see bound_chat_history) so
    an old, long-running conversation can't grow the prompt indefinitely --
    applied here, not in the caller, so every caller of this function gets
    the bound for free rather than needing to remember to apply it."""
    bounded = bound_chat_history(history)
    if not bounded:
        return "(no prior messages -- this is the first question)"
    return "\n".join(f"{turn['role']}: {turn['content']}" for turn in bounded)


def build_chat_prompt(incident: dict, chunks: list[dict], history: list[dict], message: str) -> list[BaseMessage]:
    """Render the full system+human message pair ready for llm_client.generate()."""
    return CHAT_PROMPT.format_messages(
        incident_context=format_incident_context(incident),
        retrieved_context=format_chunks(chunks),
        chat_history=format_chat_history(history),
        message=message,
    )


CRITIQUE_SYSTEM_PROMPT = """You are a fact-checking reviewer for SOC incident explanations. You \
will be given the incident's known facts, a draft explanation, and the exact source chunks the \
draft was supposed to be grounded in.

Check every factual claim in the draft against the incident context and the sources:
- A claim is SUPPORTED if it restates a fact from the incident context, or the sources directly \
state it or clearly imply it.
- A claim is NOT SUPPORTED if neither the incident context nor the sources back it up, or the \
draft goes further than what they actually say.
- Do NOT flag a claim just because it repeats a field from the incident context (e.g. the host, \
user, or process name) instead of a retrieved chunk -- incident context is first-party, known-true \
data, not something that needs a source citation.
- Pay special attention to claims that state a specific technical detail -- a command-line flag, \
parameter, encoded value, tool name, file path, or IP -- as something that happened IN THIS \
INCIDENT. Such a claim is only SUPPORTED if that exact detail appears in the incident context. A \
source chunk describing that detail as typical of the *general* technique is NOT enough to support \
it as an observed fact about this incident -- if the draft presents general technique background as \
if it were specific to this incident, flag it as NOT SUPPORTED and say the sources describe it as \
general technique behavior, not something confirmed for this incident.

""" + UNTRUSTED_EVIDENCE_RULE + """

If every claim is supported, respond with exactly: No issues found.
Otherwise, respond with one line per unsupported or low-confidence claim, each starting with \
"- ", briefly stating the claim and why it isn't supported. Do not repeat claims that are fine. \
Do not add any other commentary."""

CRITIQUE_HUMAN_PROMPT = """## Incident context (known true facts about this specific incident)
{incident_context}

## Draft explanation
{draft}

## Source chunks it should be grounded in
{retrieved_context}

## Task
List any claims in the draft that are not supported by either the incident context or the source \
chunks above, following the system instructions."""

CRITIQUE_PROMPT = ChatPromptTemplate.from_messages(
    [
        ("system", CRITIQUE_SYSTEM_PROMPT),
        ("human", CRITIQUE_HUMAN_PROMPT),
    ]
)


def build_critique_prompt(draft: str, chunks: list[dict], incident: dict) -> list[BaseMessage]:
    """Render the full system+human message pair ready for llm_client.generate()."""
    return CRITIQUE_PROMPT.format_messages(
        incident_context=format_incident_context(incident),
        draft=draft,
        retrieved_context=format_chunks(chunks),
    )


UNCOVERED_OPINION_SYSTEM_PROMPT = """You are NightOwl's advisory second-opinion assistant. You are being \
shown raw Windows telemetry that no detection rule explains -- either because it came from a \
channel/event type this deployment has no rule for, or because a rule could evaluate it but did not \
match while a narrow advisory pattern still marked it for a second look (each sample's `why_sampled` \
field says which). \
This is fundamentally different from every other role you might play in this system: you are NOT a \
detector, you cannot create alerts or incidents, and your output must never be presented or treated as a \
confirmed detection.

Some or all of this file's OTHER events may already have matched a real detection rule -- if so, those \
matches are listed below under "Already detected by a rule" and are NOT your concern; statistical \
anomaly flags (which are not rule detections) are listed separately. Your job is scoped strictly to the \
sample events shown to you, not a second verdict on the whole file. Do not re-describe or re-assess \
anything already listed as detected. You are given only the NAMES of those detections, not the events \
they matched: never state or guess which event, field or value a listed detection matched, and never say \
that something in your samples is "covered by", "explained by" or "the same as" a listed detection.

Rules you must follow:
1. Base your opinion ONLY on the sample events and retrieved context below. Do not invent facts, hosts, \
users, IPs, techniques, or event details that are not present in the input. In particular, never say what \
an identifier (an interface UUID, GUID, SID, hash, access mask or numeric code) IS or what it is used for \
unless the sample itself names it -- for an RPC interface that means the sample's `rpc_interface_name` \
field. If that field is absent, the interface is unidentified: say so, and do not link it to any technique.
2. The retrieved context chunks describe a technique in GENERAL (typical flags, tools, commands, file \
paths a threat actor might use) -- this is background, not evidence about these specific events. Only \
state that a specific flag, parameter, value, tool, or path was used IN THESE EVENTS if it literally \
appears in the sample events above. If a chunk mentions a detail the samples don't confirm, phrase it as \
what the technique commonly involves in general, never as something these events showed.
3. If nothing in the samples looks unusual, say that plainly -- do not manufacture concern just to seem \
useful. An honest "nothing stands out" is more valuable than false urgency.
4. If the retrieved context does not clearly support a claim, or the sample is too thin or ambiguous to \
judge, say so explicitly instead of guessing either way.
5. Keep your reasoning short and concrete: 2-4 sentences citing the specific process, command line, \
channel, or event type that drove your judgment (or the lack of one). When a sample includes an \
`event_type` field, use that name for what kind of event it is (e.g. "Process Terminated") -- never guess \
a meaning for the raw numeric `event_id` on your own, and never describe an event as a different kind of \
event than its own `event_type` states. If `event_type` is absent, refer to the event only by its channel \
and numeric id, not by an assumed category. You may reference a MITRE ATT&CK technique ID when the \
retrieved context supplies one relevant to what you observed, but never invent one. A retrieved technique is \
only a search result: cite it ONLY if the samples themselves show that technique's defining action (for \
example, do not name a ticket-forging technique because a ticket was requested). When the samples do not \
show it, describe what happened in plain words and name no technique.
6. End your response with EXACTLY one of these three headings, on its own line, verbatim (needed so \
callers can parse your verdict programmatically) -- choose the one that matches your judgment:
   - "## Assessment: Worth reviewing" -- something in the sample is unusual enough that a human analyst \
should look at it.
   - "## Assessment: Nothing unusual noted" -- nothing in the sample stands out as suspicious.
   - "## Assessment: Uncertain -- insufficient information" -- the sample is too limited to judge either way.
7. After the Assessment heading, add a second heading "## Limitations" on its own line, ALWAYS present \
regardless of which assessment you chose -- 1-3 short bullets stating what this analysis does NOT \
establish (e.g. how much of the file's uncovered telemetry this sample represents, what a full \
investigation would need to confirm intent, anything the retrieved context didn't cover). "Worth \
reviewing" and "the available telemetry is still insufficient to establish malicious intent" can both be \
true at once -- this heading exists specifically so both can be said, not just one or the other.
8. Never use the word "alert", "incident", or "detected" to describe your own output -- you are giving an \
opinion for a human to weigh, not raising a detection.
9. """ + UNTRUSTED_EVIDENCE_RULE

UNCOVERED_OPINION_HUMAN_PROMPT = """## File
{filename}

## Already detected by a rule (not your concern -- see system instructions)
{already_detected}

## Statistical anomaly flags (not rule detections)
{anomaly_flags}

## Sample events (not explained by any detection rule -- see each `why_sampled`)
{event_samples}

## Retrieved knowledge base context
{retrieved_context}

## Task
Give your advisory opinion on these sample events, following the system instructions."""

UNCOVERED_OPINION_PROMPT = ChatPromptTemplate.from_messages(
    [
        ("system", UNCOVERED_OPINION_SYSTEM_PROMPT),
        ("human", UNCOVERED_OPINION_HUMAN_PROMPT),
    ]
)


def format_event_samples(samples: list[dict]) -> str:
    """Render the bounded list of uncovered-event summaries
    (ai_opinion_service._event_summary's shape: channel, event_id, host,
    timestamp, process, command_line, user, event_data,
    group_total_occurrences) as numbered blocks."""
    if not samples:
        return "(no sample events available)"
    blocks = []
    for i, sample in enumerate(samples, start=1):
        lines = [
            f"- {key}: {_render_value(key, value)}" for key, value in sample.items() if value not in (None, "", [])
        ]
        blocks.append(f"[{i}]\n" + "\n".join(lines))
    return fence("\n\n".join(blocks))


def format_already_detected(matched_rule_titles: list[str]) -> str:
    if not matched_rule_titles:
        return "(no rule matched anywhere in this file)"
    return "\n".join(f"- {title}" for title in matched_rule_titles)


def format_anomaly_flags(anomaly_titles: list[str]) -> str:
    if not anomaly_titles:
        return "(none)"
    return "\n".join(f"- {title}" for title in anomaly_titles)


def build_uncovered_opinion_prompt(
    filename: str,
    samples: list[dict],
    chunks: list[dict],
    matched_rule_titles: list[str] | None = None,
    anomaly_titles: list[str] | None = None,
) -> list[BaseMessage]:
    """Render the full system+human message pair ready for llm_client.generate()."""
    return UNCOVERED_OPINION_PROMPT.format_messages(
        filename=fence(untrusted(filename, 255)),
        already_detected=format_already_detected(matched_rule_titles or []),
        anomaly_flags=format_anomaly_flags(anomaly_titles or []),
        event_samples=format_event_samples(samples),
        retrieved_context=format_chunks(chunks),
    )


ASSESSMENT_HEADINGS: dict[str, str] = {
    "## Assessment: Worth reviewing": "worth_reviewing",
    "## Assessment: Nothing unusual noted": "nothing_unusual",
    "## Assessment: Uncertain": "uncertain",  # matches the "-- insufficient information" variant too
}


def extract_assessment_label(response: str) -> str:
    """Pull the required "## Assessment: ..." heading out of a generated
    opinion and map it to a stable label for AiOpinion.assessment_label.

    Defaults to "uncertain" if no recognized heading is present (e.g. the
    LLM didn't follow the requested format) -- the safer default, since
    silently treating an unparseable response as "nothing_unusual" could
    hide something the model actually flagged.
    """
    return extract_strict_heading_label(response, ASSESSMENT_HEADINGS, default="uncertain")


RECOMMENDED_STEPS_HEADING = "## Recommended next steps"
CONFIDENCE_BREAKDOWN_HEADING = "## Confidence breakdown"
UNCOVERED_LIMITATIONS_HEADING = "## Limitations"


def _extract_section(text: str, heading: str) -> str:
    """Text between `heading` and the next "## " heading, or the end of
    `text` if there isn't a later one -- shared by every extract_* helper
    below. Stopping at the next heading (rather than just taking
    everything after `heading`, the original approach) matters now that
    "## Recommended next steps" is no longer always the last section:
    since "## Confidence breakdown" (pending.md item 5) was added after
    it, a naive "everything after" would have pulled the confidence
    breakdown into the recommended-response text too.
    """
    idx = text.find(heading)
    if idx == -1:
        return ""
    start = idx + len(heading)
    next_heading = text.find("\n## ", start)
    section = text[start:next_heading] if next_heading != -1 else text[start:]
    return section.strip()


def extract_recommended_response(explanation: str) -> str:
    """Pull the "## Recommended next steps" section out of a generated
    explanation (Day 9: exposed as its own field on the explain endpoint's
    response, alongside the full explanation).

    Returns "" if the heading isn't present -- e.g. the LLM didn't follow the
    requested format, or `explanation` is the empty string -- rather than
    raising, since the full explanation text is still returned either way.
    """
    return _extract_section(explanation, RECOMMENDED_STEPS_HEADING)


def extract_confidence_breakdown(explanation: str) -> str:
    """Pull the "## Confidence breakdown" section out of a generated
    explanation (pending.md item 5: separate FACT / INFERENCE / UNCERTAINTY
    the same mechanical way extract_recommended_response already extracts
    its own heading) -- exposed as its own field on the explain endpoint's
    response, alongside the full explanation.

    Returns "" if the heading isn't present, same reasoning as
    extract_recommended_response above.
    """
    return _extract_section(explanation, CONFIDENCE_BREAKDOWN_HEADING)


def extract_uncovered_limitations(response: str) -> str:
    """Pull the required "## Limitations" section out of a generated
    uncovered-opinion response (rule 7 of UNCOVERED_OPINION_SYSTEM_PROMPT) --
    same mechanical `_extract_section` used by the two extractors above, so
    a malformed/missing heading degrades the same documented way: "" back,
    never a raised exception. The caller (ai_opinion_service.fill_in_opinion)
    falls back to storing only the raw `summary` text when this is empty."""
    return _extract_section(response, UNCOVERED_LIMITATIONS_HEADING)


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
