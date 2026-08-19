"""Day 11 (Pair 2): app.rag.chat_service's retrieve -> answer pipeline for
incident chat. Mirrors test_explain_service.py's mocking style -- patches
`retrieve`/`generate` at their app.rag.chat_service import location, no
network or LLM call.
"""

import pytest

from app.rag import chat_service
from app.rag.llm_client import LLMProviderError

SAMPLE_CHUNKS = [
    {
        "chunk_id": "T1059.001-mitre-0",
        "document": "Adversaries may abuse PowerShell commands and scripts for execution.",
        "metadata": {"technique_id": "T1059.001", "technique_name": "PowerShell"},
        "score": 0.81,
    }
]


def test_generate_chat_reply_returns_reply_and_chunks(monkeypatch):
    monkeypatch.setattr(chat_service, "retrieve", lambda query, k, technique_id: SAMPLE_CHUNKS)
    monkeypatch.setattr(chat_service, "generate", lambda messages: "Here's the answer.")

    result = chat_service.generate_chat_reply(
        {"host": "WIN10-ANALYST", "technique_id": "T1059.001"},
        history=[],
        message="What technique was used?",
    )

    assert result.reply == "Here's the answer."
    assert result.chunks == SAMPLE_CHUNKS


def test_generate_chat_reply_includes_message_in_retrieval_query(monkeypatch):
    captured = {}

    def fake_retrieve(query, k, technique_id):
        captured["query"] = query
        return []

    monkeypatch.setattr(chat_service, "retrieve", fake_retrieve)
    monkeypatch.setattr(chat_service, "generate", lambda messages: "answer")

    chat_service.generate_chat_reply({}, history=[], message="what about lateral movement?")

    assert "lateral movement" in captured["query"]


def test_generate_chat_reply_passes_history_and_message_into_prompt(monkeypatch):
    monkeypatch.setattr(chat_service, "retrieve", lambda query, k, technique_id: [])

    captured = {}

    def fake_generate(messages):
        captured["messages"] = messages
        return "answer"

    monkeypatch.setattr(chat_service, "generate", fake_generate)

    history = [{"role": "user", "content": "first question"}, {"role": "assistant", "content": "first answer"}]
    chat_service.generate_chat_reply({}, history=history, message="second question")

    human_message = captured["messages"][1].content
    assert "first question" in human_message
    assert "first answer" in human_message
    assert "second question" in human_message


def test_generate_chat_reply_propagates_llm_provider_error(monkeypatch):
    monkeypatch.setattr(chat_service, "retrieve", lambda query, k, technique_id: [])

    def raise_error(messages):
        raise LLMProviderError("boom")

    monkeypatch.setattr(chat_service, "generate", raise_error)

    with pytest.raises(LLMProviderError):
        chat_service.generate_chat_reply({}, history=[], message="hello")
