"""Day 8 verification (Pair 2): rag/explain_service.py's retrieve -> draft ->
self-critique pipeline.

Day 12: the critique prompt templates moved to rag/prompts.py
(build_critique_prompt), and _self_critique now also passes the incident
dict through, so critique can check incident-specific claims against
incident context, not just the retrieved chunks (see
docs/research/hallucination-eval.md findings #1/#2).

Runs fully offline -- retriever.retrieve and llm_client.generate are both
mocked, no network call and no real LLM_API_KEY is needed or used.
"""

import pytest

from app.rag import explain_service
from app.rag.explain_service import ExplanationResult, _build_retrieval_query, generate_explanation

SAMPLE_INCIDENT = {
    "host": "WIN10-ANALYST",
    "process": "powershell.exe",
    "command_line": "powershell.exe -enc SQBFAFgA...",
    "user": "jdoe",
    "technique_id": "T1059.001",
}

SAMPLE_CHUNKS = [
    {
        "chunk_id": "T1059.001-mitre-0",
        "document": "Adversaries may abuse PowerShell commands and scripts for execution.",
        "metadata": {"technique_id": "T1059.001", "technique_name": "PowerShell"},
        "score": 0.81,
    }
]


def test_build_retrieval_query_combines_available_fields():
    query = _build_retrieval_query(SAMPLE_INCIDENT)

    assert "T1059.001" in query
    assert "powershell.exe" in query


def test_build_retrieval_query_falls_back_when_incident_is_sparse():
    assert _build_retrieval_query({}) == "security incident"


def test_generate_explanation_no_issues_found_returns_draft_unchanged(monkeypatch):
    monkeypatch.setattr(explain_service, "retrieve", lambda query, k, technique_id: SAMPLE_CHUNKS)
    responses = iter(["draft explanation text", "No issues found."])
    monkeypatch.setattr(explain_service, "generate", lambda messages: next(responses))

    result = generate_explanation(SAMPLE_INCIDENT)

    assert isinstance(result, ExplanationResult)
    assert result.draft == "draft explanation text"
    assert result.critique is None
    assert result.explanation == "draft explanation text"
    assert result.chunks == SAMPLE_CHUNKS


def test_generate_explanation_appends_critique_when_issues_found(monkeypatch):
    monkeypatch.setattr(explain_service, "retrieve", lambda query, k, technique_id: SAMPLE_CHUNKS)
    responses = iter(
        [
            "draft explanation text",
            "- The draft claims the host was compromised, but the sources don't support that.",
        ]
    )
    monkeypatch.setattr(explain_service, "generate", lambda messages: next(responses))

    result = generate_explanation(SAMPLE_INCIDENT)

    assert result.draft == "draft explanation text"
    assert result.critique is not None
    assert "compromised" in result.critique
    assert result.explanation.startswith("draft explanation text")
    assert "**Confidence check:**" in result.explanation
    assert result.critique in result.explanation


def test_generate_explanation_passes_technique_id_and_k_to_retrieve(monkeypatch):
    captured = {}

    def fake_retrieve(query, k, technique_id):
        captured["query"] = query
        captured["k"] = k
        captured["technique_id"] = technique_id
        return SAMPLE_CHUNKS

    monkeypatch.setattr(explain_service, "retrieve", fake_retrieve)
    responses = iter(["draft", "No issues found."])
    monkeypatch.setattr(explain_service, "generate", lambda messages: next(responses))

    generate_explanation(SAMPLE_INCIDENT, k=3)

    assert captured["technique_id"] == "T1059.001"
    assert captured["k"] == 3


def test_generate_explanation_passes_incident_into_critique_prompt(monkeypatch):
    monkeypatch.setattr(explain_service, "retrieve", lambda query, k, technique_id: SAMPLE_CHUNKS)
    responses = iter(["draft explanation text", "No issues found."])
    monkeypatch.setattr(explain_service, "generate", lambda messages: next(responses))

    captured = {}
    real_build_critique_prompt = explain_service.build_critique_prompt

    def capturing_build_critique_prompt(draft, chunks, incident):
        captured["draft"] = draft
        captured["chunks"] = chunks
        captured["incident"] = incident
        return real_build_critique_prompt(draft, chunks, incident)

    monkeypatch.setattr(explain_service, "build_critique_prompt", capturing_build_critique_prompt)

    generate_explanation(SAMPLE_INCIDENT)

    assert captured["incident"] == SAMPLE_INCIDENT
    assert captured["draft"] == "draft explanation text"
    assert captured["chunks"] == SAMPLE_CHUNKS


def test_generate_explanation_propagates_llm_provider_error(monkeypatch):
    from app.rag.llm_client import LLMProviderError

    monkeypatch.setattr(explain_service, "retrieve", lambda query, k, technique_id: SAMPLE_CHUNKS)

    def raise_error(messages):
        raise LLMProviderError("LLM call failed after 2 attempts: boom")

    monkeypatch.setattr(explain_service, "generate", raise_error)

    with pytest.raises(LLMProviderError):
        generate_explanation(SAMPLE_INCIDENT)
