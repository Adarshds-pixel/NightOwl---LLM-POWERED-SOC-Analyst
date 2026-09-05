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
7. Keep the whole response under ~350 words. Do not repeat the raw input back verbatim."""

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
shown raw Windows telemetry that NO detection rule was able to evaluate -- either because it came from a \
channel/event type this deployment has no rule for, or because it fell outside every loaded rule's scope. \
This is fundamentally different from every other role you might play in this system: you are NOT a \
detector, you cannot create alerts or incidents, and your output must never be presented or treated as a \
confirmed detection.

Rules you must follow:
1. Base your opinion ONLY on the sample events and retrieved context below. Do not invent facts, hosts, \
users, IPs, or techniques that are not present in the input.
2. If nothing in the samples looks unusual, say that plainly -- do not manufacture concern just to seem \
useful. An honest "nothing stands out" is more valuable than false urgency.
3. If you are genuinely unsure because the sample is too thin or ambiguous to judge, say so explicitly \
rather than guessing either way.
4. Keep your reasoning short and concrete: 2-4 sentences citing the specific process, command line, \
channel, or event type that drove your judgment (or the lack of one).
5. End your response with EXACTLY one of these three headings, on its own line, verbatim (needed so \
callers can parse your verdict programmatically) -- choose the one that matches your judgment:
   - "## Assessment: Worth reviewing" -- something in the sample is unusual enough that a human analyst \
should look at it.
   - "## Assessment: Nothing unusual noted" -- nothing in the sample stands out as suspicious.
   - "## Assessment: Uncertain -- insufficient information" -- the sample is too limited to judge either way.
6. Never use the word "alert", "incident", or "detected" to describe your own output -- you are giving an \
opinion for a human to weigh, not raising a detection."""

UNCOVERED_OPINION_HUMAN_PROMPT = """## File
{filename}

## Sample events (no loaded rule could evaluate these)
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
    timestamp, process, command_line, user) as numbered blocks."""
    if not samples:
        return "(no sample events available)"
    blocks = []
    for i, sample in enumerate(samples, start=1):
        lines = [f"- {key}: {value}" for key, value in sample.items() if value not in (None, "", [])]
        blocks.append(f"[{i}]\n" + "\n".join(lines))
    return "\n\n".join(blocks)


def build_uncovered_opinion_prompt(filename: str, samples: list[dict], chunks: list[dict]) -> list[BaseMessage]:
    """Render the full system+human message pair ready for llm_client.generate()."""
    return UNCOVERED_OPINION_PROMPT.format_messages(
        filename=filename,
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
    for heading, label in ASSESSMENT_HEADINGS.items():
        if heading in response:
            return label
    return "uncertain"


RECOMMENDED_STEPS_HEADING = "## Recommended next steps"
CONFIDENCE_BREAKDOWN_HEADING = "## Confidence breakdown"


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
