"""Day 7 verification (Pair 2): rag/prompts.py's explanation prompt template.
Day 11 adds cases for the chat prompt template (format_chat_history,
build_chat_prompt). Day 12 adds cases for build_critique_prompt (moved here
from explain_service.py) and the new "general technique background vs.
observed fact about this incident" guard rule in both system prompts.

Pure string/template tests -- no network, no API key needed.
"""

from langchain_core.messages import HumanMessage, SystemMessage

from app.rag.prompts import (
    CHAT_SYSTEM_PROMPT,
    SYSTEM_PROMPT,
    build_chat_prompt,
    build_critique_prompt,
    build_explanation_prompt,
    extract_recommended_response,
    format_chat_history,
    format_chunks,
    format_incident_context,
)

SAMPLE_INCIDENT = {
    "host": "WIN10-ANALYST",
    "process": "powershell.exe",
    "command_line": "powershell.exe -enc SQBFAFgA...",
    "user": "jdoe",
}

SAMPLE_CHUNKS = [
    {
        "chunk_id": "T1059.001-mitre-0",
        "document": "Adversaries may abuse PowerShell commands and scripts for execution.",
        "metadata": {"technique_id": "T1059.001", "technique_name": "PowerShell", "tactics": "execution"},
        "score": 0.8123,
    }
]


def test_format_incident_context_renders_all_fields():
    rendered = format_incident_context(SAMPLE_INCIDENT)

    assert "host: WIN10-ANALYST" in rendered
    assert "process: powershell.exe" in rendered
    assert "user: jdoe" in rendered


def test_format_incident_context_drops_empty_fields():
    rendered = format_incident_context({"host": "WIN10-ANALYST", "user": None, "protocol": ""})

    assert "host: WIN10-ANALYST" in rendered
    assert "user" not in rendered
    assert "protocol" not in rendered


def test_format_incident_context_empty_dict():
    assert format_incident_context({}) == "(no incident context provided)"


def test_format_chunks_includes_document_score_and_metadata():
    rendered = format_chunks(SAMPLE_CHUNKS)

    assert "Adversaries may abuse PowerShell" in rendered
    assert "0.812" in rendered
    assert "technique_id=T1059.001" in rendered


def test_format_chunks_empty_list():
    assert format_chunks([]) == "(no relevant knowledge base context retrieved)"


def test_build_explanation_prompt_returns_system_and_human_messages():
    messages = build_explanation_prompt(SAMPLE_INCIDENT, SAMPLE_CHUNKS)

    assert len(messages) == 2
    assert isinstance(messages[0], SystemMessage)
    assert isinstance(messages[1], HumanMessage)


def test_build_explanation_prompt_system_message_carries_grounding_rules():
    messages = build_explanation_prompt(SAMPLE_INCIDENT, SAMPLE_CHUNKS)

    system_text = messages[0].content
    assert "junior analyst" in system_text
    assert "Do not invent facts" in system_text


def test_system_prompt_distinguishes_general_technique_background_from_incident_fact():
    """Day 10 hallucination-eval.md finding #2: a draft claimed an -enc
    flag the crafted incident never had, imported from a retrieved
    playbook's general technique description. Both generation system
    prompts must tell the LLM not to state general technique background as
    an observed fact about this specific incident."""
    assert "IN THIS INCIDENT" in SYSTEM_PROMPT
    assert "IN THIS INCIDENT" in CHAT_SYSTEM_PROMPT


def test_build_explanation_prompt_human_message_embeds_incident_and_technique_id():
    messages = build_explanation_prompt(SAMPLE_INCIDENT, SAMPLE_CHUNKS)

    human_text = messages[1].content
    assert "WIN10-ANALYST" in human_text
    assert "T1059.001" in human_text


def test_build_explanation_prompt_handles_no_chunks():
    messages = build_explanation_prompt(SAMPLE_INCIDENT, [])

    assert "no relevant knowledge base context retrieved" in messages[1].content


def test_extract_recommended_response_returns_text_after_heading():
    explanation = (
        "## What happened\nSomething happened.\n\n"
        "## Why it matters\nIt matters.\n\n"
        "## Recommended next steps\n- Isolate the host.\n- Capture memory."
    )

    assert extract_recommended_response(explanation) == "- Isolate the host.\n- Capture memory."


def test_extract_recommended_response_missing_heading_returns_empty_string():
    assert extract_recommended_response("## What happened\nSomething happened.") == ""


def test_extract_recommended_response_empty_string():
    assert extract_recommended_response("") == ""


def test_format_chat_history_empty_list():
    assert format_chat_history([]) == "(no prior messages -- this is the first question)"


def test_format_chat_history_renders_role_and_content_lines():
    history = [
        {"role": "user", "content": "What happened?"},
        {"role": "assistant", "content": "PowerShell was used for execution."},
    ]

    rendered = format_chat_history(history)

    assert "user: What happened?" in rendered
    assert "assistant: PowerShell was used for execution." in rendered


def test_build_chat_prompt_returns_system_and_human_messages():
    messages = build_chat_prompt(SAMPLE_INCIDENT, SAMPLE_CHUNKS, [], "Why was this flagged?")

    assert len(messages) == 2
    assert isinstance(messages[0], SystemMessage)
    assert isinstance(messages[1], HumanMessage)


def test_build_chat_prompt_human_message_embeds_incident_history_and_question():
    history = [{"role": "user", "content": "What happened?"}, {"role": "assistant", "content": "PowerShell ran."}]

    messages = build_chat_prompt(SAMPLE_INCIDENT, SAMPLE_CHUNKS, history, "What about the host?")

    human_text = messages[1].content
    assert "WIN10-ANALYST" in human_text
    assert "PowerShell ran." in human_text
    assert "What about the host?" in human_text


def test_build_chat_prompt_handles_no_history_or_chunks():
    messages = build_chat_prompt(SAMPLE_INCIDENT, [], [], "Why was this flagged?")

    human_text = messages[1].content
    assert "no prior messages" in human_text
    assert "no relevant knowledge base context retrieved" in human_text


def test_build_critique_prompt_returns_system_and_human_messages():
    messages = build_critique_prompt("draft text", SAMPLE_CHUNKS, SAMPLE_INCIDENT)

    assert len(messages) == 2
    assert isinstance(messages[0], SystemMessage)
    assert isinstance(messages[1], HumanMessage)


def test_build_critique_prompt_system_message_treats_incident_context_as_legitimate():
    """Day 10 hallucination-eval.md finding #1: critique used to flag the
    incident's own context fields (e.g. host) as unsupported, because it
    never saw incident context, only retrieved chunks."""
    messages = build_critique_prompt("draft text", SAMPLE_CHUNKS, SAMPLE_INCIDENT)

    system_text = messages[0].content
    assert "incident context" in system_text.lower()
    assert "first-party" in system_text.lower()


def test_build_critique_prompt_human_message_embeds_draft_chunks_and_incident():
    messages = build_critique_prompt("draft text goes here", SAMPLE_CHUNKS, SAMPLE_INCIDENT)

    human_text = messages[1].content
    assert "draft text goes here" in human_text
    assert "Adversaries may abuse PowerShell" in human_text
    assert "WIN10-ANALYST" in human_text


def test_build_critique_prompt_handles_empty_chunks_and_incident():
    messages = build_critique_prompt("draft text", [], {})

    human_text = messages[1].content
    assert "no relevant knowledge base context retrieved" in human_text
    assert "no incident context provided" in human_text
