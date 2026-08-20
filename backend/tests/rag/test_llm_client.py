"""Day 7 verification (Pair 2): rag/llm_client.py's Gemini wrapper.

Day 12 adds: an explicit request timeout on both provider constructors, a
Groq construction test (previously untested), the opt-in response cache,
and generate_with_metrics() for the token-usage/latency measurement script.

Runs fully offline -- ChatGoogleGenerativeAI/ChatGroq are mocked
throughout, no network call and no real API key is needed or used.
"""

import pytest

from app.core.config import settings
from app.rag import llm_client
from app.rag.llm_client import LLMProviderError, generate, generate_with_metrics, get_llm_client


class FakeResponse:
    def __init__(self, content, usage_metadata=None):
        self.content = content
        if usage_metadata is not None:
            self.usage_metadata = usage_metadata


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


class FakeChatGroq:
    """Records constructor kwargs; .invoke() behavior is set per-test."""

    last_kwargs = None
    invoke_side_effect = None

    def __init__(self, **kwargs):
        FakeChatGroq.last_kwargs = kwargs

    def invoke(self, messages):
        effect = FakeChatGroq.invoke_side_effect
        if callable(effect):
            return effect(messages)
        if isinstance(effect, Exception):
            raise effect
        return FakeResponse(effect)


@pytest.fixture(autouse=True)
def reset_llm_client_state(monkeypatch):
    """llm_client caches its client (and, since Day 12, responses) in
    module-level globals -- reset them before and after every test so
    tests don't leak state into each other."""
    monkeypatch.setattr(llm_client, "_client", None)
    monkeypatch.setattr(llm_client, "_response_cache", {})
    monkeypatch.setattr(llm_client, "ChatGoogleGenerativeAI", FakeChatGoogleGenerativeAI)
    monkeypatch.setattr(llm_client, "ChatGroq", FakeChatGroq)
    monkeypatch.setattr(settings, "llm_cache_enabled", False)
    FakeChatGoogleGenerativeAI.last_kwargs = None
    FakeChatGoogleGenerativeAI.invoke_side_effect = None
    FakeChatGroq.last_kwargs = None
    FakeChatGroq.invoke_side_effect = None
    yield
    monkeypatch.setattr(llm_client, "_client", None)
    monkeypatch.setattr(llm_client, "_response_cache", {})


def test_get_llm_client_raises_when_api_key_missing(monkeypatch):
    monkeypatch.setattr(settings, "llm_api_key", "")

    with pytest.raises(LLMProviderError, match="LLM_API_KEY"):
        get_llm_client()


def test_get_llm_client_constructs_with_configured_model_and_key(monkeypatch):
    monkeypatch.setattr(settings, "llm_api_key", "fake-key")
    monkeypatch.setattr(settings, "llm_model", "gemini-flash-latest")
    monkeypatch.setattr(settings, "llm_timeout_seconds", 30.0)

    client = get_llm_client()

    assert isinstance(client, FakeChatGoogleGenerativeAI)
    assert FakeChatGoogleGenerativeAI.last_kwargs == {
        "model": "gemini-flash-latest",
        "google_api_key": "fake-key",
        "timeout": 30.0,
    }


def test_get_llm_client_is_cached(monkeypatch):
    monkeypatch.setattr(settings, "llm_api_key", "fake-key")

    first = get_llm_client()
    second = get_llm_client()

    assert first is second


def test_get_llm_client_raises_when_groq_api_key_missing(monkeypatch):
    monkeypatch.setattr(settings, "llm_provider", "groq")
    monkeypatch.setattr(settings, "groq_api_key", "")

    with pytest.raises(LLMProviderError, match="GROQ_API_KEY"):
        get_llm_client()


def test_get_llm_client_constructs_groq_with_configured_model_key_and_timeout(monkeypatch):
    monkeypatch.setattr(settings, "llm_provider", "groq")
    monkeypatch.setattr(settings, "groq_api_key", "fake-groq-key")
    monkeypatch.setattr(settings, "groq_model", "openai/gpt-oss-120b")
    monkeypatch.setattr(settings, "llm_timeout_seconds", 30.0)

    client = get_llm_client()

    assert isinstance(client, FakeChatGroq)
    assert FakeChatGroq.last_kwargs == {
        "model": "openai/gpt-oss-120b",
        "api_key": "fake-groq-key",
        "request_timeout": 30.0,
    }


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


def test_generate_bypasses_cache_by_default(monkeypatch):
    """llm_cache_enabled defaults to False -- an identical call still hits
    the provider every time."""
    monkeypatch.setattr(settings, "llm_api_key", "fake-key")
    calls = []

    def count_calls(messages):
        calls.append(messages)
        return FakeResponse("same answer")

    FakeChatGoogleGenerativeAI.invoke_side_effect = count_calls

    generate([])
    generate([])

    assert len(calls) == 2


def test_generate_caches_identical_calls_when_enabled(monkeypatch):
    monkeypatch.setattr(settings, "llm_api_key", "fake-key")
    monkeypatch.setattr(settings, "llm_cache_enabled", True)
    calls = []

    def count_calls(messages):
        calls.append(messages)
        return FakeResponse("cached answer")

    FakeChatGoogleGenerativeAI.invoke_side_effect = count_calls

    first = generate([])
    second = generate([])

    assert first == second == "cached answer"
    assert len(calls) == 1


def test_generate_cache_misses_on_different_message_content(monkeypatch):
    from langchain_core.messages import HumanMessage

    monkeypatch.setattr(settings, "llm_api_key", "fake-key")
    monkeypatch.setattr(settings, "llm_cache_enabled", True)
    calls = []

    def echo(messages):
        calls.append(messages)
        return FakeResponse(f"answer for {messages[0].content}")

    FakeChatGoogleGenerativeAI.invoke_side_effect = echo

    generate([HumanMessage(content="question one")])
    generate([HumanMessage(content="question two")])

    assert len(calls) == 2


def test_generate_never_caches_a_failed_call(monkeypatch):
    monkeypatch.setattr(settings, "llm_api_key", "fake-key")
    monkeypatch.setattr(settings, "llm_cache_enabled", True)
    monkeypatch.setattr(llm_client, "_RETRY_DELAY_SECONDS", 0)

    FakeChatGoogleGenerativeAI.invoke_side_effect = RuntimeError("boom")
    with pytest.raises(LLMProviderError):
        generate([])

    FakeChatGoogleGenerativeAI.invoke_side_effect = "recovered"
    result = generate([])

    assert result == "recovered"


def test_generate_with_metrics_captures_usage_and_latency(monkeypatch):
    monkeypatch.setattr(settings, "llm_api_key", "fake-key")
    monkeypatch.setattr(settings, "llm_provider", "gemini")
    monkeypatch.setattr(settings, "llm_model", "gemini-flash-latest")
    FakeChatGoogleGenerativeAI.invoke_side_effect = lambda messages: FakeResponse(
        "an explanation",
        usage_metadata={"input_tokens": 120, "output_tokens": 45, "total_tokens": 165},
    )

    metrics = generate_with_metrics([])

    assert metrics.text == "an explanation"
    assert metrics.input_tokens == 120
    assert metrics.output_tokens == 45
    assert metrics.total_tokens == 165
    assert metrics.latency_seconds >= 0
    assert metrics.provider == "gemini"
    assert metrics.model == "gemini-flash-latest"


def test_generate_with_metrics_falls_back_to_none_when_usage_absent(monkeypatch):
    """A mocked/older response with no usage_metadata attribute at all
    shouldn't raise -- metrics come back as None, not an error."""
    monkeypatch.setattr(settings, "llm_api_key", "fake-key")
    FakeChatGoogleGenerativeAI.invoke_side_effect = "an explanation"

    metrics = generate_with_metrics([])

    assert metrics.text == "an explanation"
    assert metrics.input_tokens is None
    assert metrics.output_tokens is None
    assert metrics.total_tokens is None


def test_generate_with_metrics_does_not_use_cache(monkeypatch):
    """Metrics are meant to measure a real call -- caching would make
    repeated measurements meaningless, so generate_with_metrics always
    invokes the provider even when llm_cache_enabled is on."""
    monkeypatch.setattr(settings, "llm_api_key", "fake-key")
    monkeypatch.setattr(settings, "llm_cache_enabled", True)
    calls = []

    def count_calls(messages):
        calls.append(messages)
        return FakeResponse("answer")

    FakeChatGoogleGenerativeAI.invoke_side_effect = count_calls

    generate_with_metrics([])
    generate_with_metrics([])

    assert len(calls) == 2
