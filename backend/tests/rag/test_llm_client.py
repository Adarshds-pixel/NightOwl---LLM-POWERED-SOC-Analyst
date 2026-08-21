"""Day 7 verification (Pair 2): rag/llm_client.py's Gemini wrapper.

Runs fully offline -- ChatGoogleGenerativeAI is mocked throughout, no
network call and no real LLM_API_KEY is needed or used.
"""

import pytest

from app.core.config import settings
from app.rag import llm_client
from app.rag.llm_client import LLMProviderError, generate, get_llm_client


class FakeResponse:
    def __init__(self, content):
        self.content = content


class FakeChatGoogleGenerativeAI:
    """Records constructor kwargs; .invoke() behavior is set per-test."""

    last_kwargs = None
    invoke_side_effect = None

    def __init__(self, **kwargs):
        FakeChatGoogleGenerativeAI.last_kwargs = kwargs

    def invoke(self, messages):
        effect = FakeChatGoogleGenerativeAI.invoke_side_effect
        if callable(effect):
            return effect(messages)
        if isinstance(effect, Exception):
            raise effect
        return FakeResponse(effect)


@pytest.fixture(autouse=True)
def reset_llm_client_state(monkeypatch):
    """llm_client caches its client in a module-level global -- reset it
    before and after every test so tests don't leak state into each other."""
    monkeypatch.setattr(llm_client, "_client", None)
    monkeypatch.setattr(llm_client, "ChatGoogleGenerativeAI", FakeChatGoogleGenerativeAI)
    FakeChatGoogleGenerativeAI.last_kwargs = None
    FakeChatGoogleGenerativeAI.invoke_side_effect = None
    yield
    monkeypatch.setattr(llm_client, "_client", None)


def test_get_llm_client_raises_when_api_key_missing(monkeypatch):
    monkeypatch.setattr(settings, "llm_api_key", "")

    with pytest.raises(LLMProviderError, match="LLM_API_KEY"):
        get_llm_client()


def test_get_llm_client_constructs_with_configured_model_and_key(monkeypatch):
    monkeypatch.setattr(settings, "llm_api_key", "fake-key")
    monkeypatch.setattr(settings, "llm_model", "gemini-flash-latest")
    monkeypatch.setattr(settings, "llm_timeout_seconds", 30)

    client = get_llm_client()

    assert isinstance(client, FakeChatGoogleGenerativeAI)
    assert FakeChatGoogleGenerativeAI.last_kwargs == {
        "model": "gemini-flash-latest",
        "google_api_key": "fake-key",
        "timeout": 30,
        "max_retries": 1,
    }


def test_get_llm_client_passes_timeout_for_groq(monkeypatch):
    """A stalled network call must fail within llm_timeout_seconds instead of
    blocking the request thread forever -- confirmed by tracing langchain's
    client -> httpx, which defaults to Timeout(None) (no timeout at any
    layer) when none is passed. Covers the Groq branch; the Gemini branch is
    covered by test_get_llm_client_constructs_with_configured_model_and_key.
    """

    class FakeChatGroq:
        last_kwargs = None

        def __init__(self, **kwargs):
            FakeChatGroq.last_kwargs = kwargs

    monkeypatch.setattr(llm_client, "ChatGroq", FakeChatGroq)
    monkeypatch.setattr(settings, "llm_provider", "groq")
    monkeypatch.setattr(settings, "groq_api_key", "fake-groq-key")
    monkeypatch.setattr(settings, "groq_model", "openai/gpt-oss-120b")
    monkeypatch.setattr(settings, "llm_timeout_seconds", 45)

    client = get_llm_client()

    assert isinstance(client, FakeChatGroq)
    assert FakeChatGroq.last_kwargs == {
        "model": "openai/gpt-oss-120b",
        "api_key": "fake-groq-key",
        "timeout": 45,
        "max_retries": 0,
    }


def test_get_llm_client_is_cached(monkeypatch):
    monkeypatch.setattr(settings, "llm_api_key", "fake-key")

    first = get_llm_client()
    second = get_llm_client()

    assert first is second


def test_generate_returns_mocked_content_on_success(monkeypatch):
    monkeypatch.setattr(settings, "llm_api_key", "fake-key")
    FakeChatGoogleGenerativeAI.invoke_side_effect = "explanation text"

    result = generate([])

    assert result == "explanation text"


def test_generate_retries_once_then_raises_after_repeated_failure(monkeypatch):
    monkeypatch.setattr(settings, "llm_api_key", "fake-key")
    monkeypatch.setattr(llm_client, "_RETRY_DELAY_SECONDS", 0)
    calls = []

    def always_fail(messages):
        calls.append(messages)
        raise RuntimeError("provider unavailable")

    FakeChatGoogleGenerativeAI.invoke_side_effect = always_fail

    with pytest.raises(LLMProviderError, match="failed after 2 attempts"):
        generate([])

    assert len(calls) == 2


def test_generate_recovers_if_retry_succeeds(monkeypatch):
    monkeypatch.setattr(settings, "llm_api_key", "fake-key")
    monkeypatch.setattr(llm_client, "_RETRY_DELAY_SECONDS", 0)
    attempts = {"count": 0}

    def fail_once_then_succeed(messages):
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise RuntimeError("transient error")
        return FakeResponse("recovered explanation")

    FakeChatGoogleGenerativeAI.invoke_side_effect = fail_once_then_succeed

    result = generate([])

    assert result == "recovered explanation"
    assert attempts["count"] == 2


def test_generate_raises_on_empty_response(monkeypatch):
    monkeypatch.setattr(settings, "llm_api_key", "fake-key")
    monkeypatch.setattr(llm_client, "_RETRY_DELAY_SECONDS", 0)
    FakeChatGoogleGenerativeAI.invoke_side_effect = ""

    with pytest.raises(LLMProviderError, match="failed after 2 attempts"):
        generate([])


def test_generate_extracts_text_from_content_block_list(monkeypatch):
    """Real Gemini responses return `content` as a list of content blocks
    (e.g. [{"type": "text", "text": ..., "extras": {...}}]), not a plain
    string -- confirmed via a live call. generate() must unwrap this."""
    monkeypatch.setattr(settings, "llm_api_key", "fake-key")
    FakeChatGoogleGenerativeAI.invoke_side_effect = [
        {"type": "text", "text": "part one. ", "extras": {"signature": "abc"}},
        {"type": "text", "text": "part two."},
    ]

    result = generate([])

    assert result == "part one. part two."
