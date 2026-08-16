"""Day 7 verification (Pair 2): rag/prompts.py's explanation prompt template.

Pure string/template tests -- no network, no API key needed.
"""

from langchain_core.messages import HumanMessage, SystemMessage

from app.rag.prompts import build_explanation_prompt, format_chunks, format_incident_context

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


def test_build_explanation_prompt_human_message_embeds_incident_and_technique_id():
    messages = build_explanation_prompt(SAMPLE_INCIDENT, SAMPLE_CHUNKS)

    human_text = messages[1].content
    assert "WIN10-ANALYST" in human_text
    assert "T1059.001" in human_text


def test_build_explanation_prompt_handles_no_chunks():
    messages = build_explanation_prompt(SAMPLE_INCIDENT, [])

    assert "no relevant knowledge base context retrieved" in messages[1].content
