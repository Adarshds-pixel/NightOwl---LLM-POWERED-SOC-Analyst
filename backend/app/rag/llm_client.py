"""LangChain-wired client for NightOwl's LLM provider: Groq, exclusively.

Kept as a thin wrapper around the provider-specific LangChain chat client,
rather than importing the SDK directly elsewhere, so:
  - the rest of the app (explain_service.py, chat_service.py) never
    imports langchain_groq directly -- this is the one file that would
    need to change if that ever stopped being true.
  - failures (missing key, quota, network) come back as one
    LLMProviderError instead of leaking provider-specific exceptions up
    through unrelated call sites: app -> Groq client -> Groq API -> a
    clean LLMProviderError (503 at the API layer, see core/errors.py) on
    any failure. No automatic fallback to another provider on failure --
    a provider outage is a clean, visible error, not a silent swap.

Groq-only as of 2026-09-06 (see docs/ARCHITECTURE.md's decision log): this
project previously supported Gemini as an alternate provider behind
`settings.llm_provider`, removed once Gemini's free tier proved
structurally unreliable for this project's call volume (a hard 20-req/day
quota plus separate server-side 503/504 overload, both observed live) --
Groq had already been the actually-configured provider for some time
before the Gemini code path was removed. Historical: git history has the
removed dual-provider code if it's ever needed for reference.

Day 12 robustness additions (still apply, provider-agnostic):
  - An explicit `timeout` on client construction, so a hung provider call
    surfaces as a timeout exception (caught by generate()'s existing
    retry/LLMProviderError wrapping) instead of blocking indefinitely.
  - An opt-in in-memory response cache (`settings.llm_cache_enabled`,
    default off) keyed on exact prompt content, to avoid burning through a
    tight free-tier daily quota on repeated identical calls during manual
    testing.
  - `generate_with_metrics()`, alongside the existing `generate()`, for the
    Day 12 token-usage/latency measurement script -- kept separate so
    `generate()`'s `-> str` contract (and every existing caller/test) is
    unchanged.

Also pins the client's own internal retry count to 0 (see get_llm_client()):
the SDK would otherwise retry several times internally with its own
backoff before an exception ever reaches generate()'s retry-once, which
stacks under it and can turn a single failed call into a very long wait
before any error surfaces.
"""

import hashlib
import logging
import time
from dataclasses import dataclass

from langchain_core.messages import BaseMessage
from langchain_groq import ChatGroq

from app.core.config import settings

logger = logging.getLogger(__name__)

_MAX_ATTEMPTS = 2  # one retry -- keep simple, this is a student project not a production SLA
_RETRY_DELAY_SECONDS = 2


class LLMProviderError(Exception):
    """Raised when Groq can't produce a response (missing/invalid API key,
    network failure, rate limit, empty response)."""


_client: ChatGroq | None = None

# Day 12: opt-in response cache, keyed on a hash of the exact rendered
# prompt content. Only ever populated on a *successful* call -- a failed
# call is never cached, so a transient provider error doesn't get "stuck".
_response_cache: dict[str, str] = {}


@dataclass
class GenerationMetrics:
    """Everything scripts/llm_cost_latency_check.py needs to report token
    usage and latency per call -- not used on the hot request path
    (explain_service.py/chat_service.py keep calling plain generate())."""

    text: str
    input_tokens: int | None
    output_tokens: int | None
    total_tokens: int | None
    latency_seconds: float
    provider: str
    model: str


def _cache_key(messages: list[BaseMessage]) -> str:
    rendered = "|".join(f"{m.type}:{m.content}" for m in messages)
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def _extract_text(content) -> str:
    """Normalize an AIMessage's `content` into plain text.

    LangChain chat models may return `content` either as a plain string or as
    a list of content blocks ([{"type": "text", "text": ...}, ...]);
    concatenate just the text blocks.
    """
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(
            block.get("text", "")
            for block in content
            if isinstance(block, dict) and block.get("type") == "text"
        )
    return ""


def get_llm_client() -> ChatGroq:
    """Return a cached Groq chat client.

    Raises LLMProviderError immediately if no API key is configured, rather
    than waiting for the SDK to fail with an ambiguous auth error deep in a
    generate() call. No fallback to any other provider -- a missing key or
    a Groq-side failure surfaces as a clean error (see module docstring).
    """
    global _client
    if _client is not None:
        return _client

    if not settings.groq_api_key:
        raise LLMProviderError(
            "GROQ_API_KEY is not set -- add a free Groq API key from https://console.groq.com/keys"
        )
    # ChatGroq's timeout field is named `request_timeout`, not `timeout` --
    # confirmed against the installed langchain-groq version's Pydantic
    # fields. max_retries=0: generate() already retries once itself (see
    # module docstring) -- stacking the SDK's own retries under that would
    # turn one failed call into a very long wait.
    _client = ChatGroq(
        model=settings.groq_model,
        api_key=settings.groq_api_key,
        request_timeout=settings.llm_timeout_seconds,
        max_retries=0,
    )
    return _client


def _status_code(exc: Exception) -> int | None:
    for attr in ("status_code", "status"):
        value = getattr(exc, attr, None)
        if isinstance(value, int):
            return value
    response = getattr(exc, "response", None)
    value = getattr(response, "status_code", None)
    return value if isinstance(value, int) else None


def _public_reason(exc: Exception) -> str:
    """What the API tells the client. The provider's raw exception text (which
    can include request ids, account details or upstream URLs) is logged, not
    returned."""
    status = _status_code(exc)
    name = type(exc).__name__.lower()
    if status == 429 or "ratelimit" in name:
        return "the AI provider's rate limit was reached -- try again in a minute"
    if status in (401, 403) or "authentication" in name or "permission" in name:
        return "the AI provider rejected the configured API key"
    if "timeout" in name:
        return "the AI provider did not respond in time"
    if isinstance(exc, LLMProviderError):
        return str(exc)
    return "the AI provider is unavailable right now"


def _is_retryable(exc: Exception) -> bool:
    # A 4xx (bad key, quota exhausted, bad request) will fail identically on
    # retry and a retry spends more of a free-tier quota; only transient
    # failures (timeouts, 5xx, connection errors, empty replies) are retried.
    status = _status_code(exc)
    return status is None or status >= 500


def _generate_raw(messages: list[BaseMessage]) -> tuple[object, str]:
    """Send `messages` to the LLM, retrying once on transient failure.
    Returns the raw provider response alongside the extracted text, so
    callers that need more than text (generate_with_metrics) don't have to
    re-invoke the client."""
    client = get_llm_client()

    last_error: Exception | None = None
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        try:
            response = client.invoke(messages)
            text = _extract_text(getattr(response, "content", None))
            if not text:
                raise LLMProviderError("LLM returned an empty response")
            return response, text
        except Exception as exc:  # noqa: BLE001 -- deliberately broad: SDK can raise many types
            last_error = exc
            logger.warning("LLM call failed (attempt %d/%d): %r", attempt, _MAX_ATTEMPTS, exc)
            if attempt < _MAX_ATTEMPTS and _is_retryable(exc):
                time.sleep(_RETRY_DELAY_SECONDS)
                continue
            break

    raise LLMProviderError(f"AI request failed: {_public_reason(last_error)}") from last_error


def generate(messages: list[BaseMessage]) -> str:
    """Send `messages` (as produced by rag/prompts.py) to the LLM and return
    its text response, retrying once on transient failure.

    If `settings.llm_cache_enabled` is set, an exact repeat of `messages`
    returns the previously cached response instead of calling the provider
    again -- opt-in, off by default, meant for repeated manual testing
    against a tight free-tier quota, not production behavior."""
    if settings.llm_cache_enabled:
        key = _cache_key(messages)
        cached = _response_cache.get(key)
        if cached is not None:
            logger.debug("llm_client cache hit")
            return cached

        text = _generate_raw(messages)[1]
        _response_cache[key] = text
        return text

    return _generate_raw(messages)[1]


def generate_with_metrics(messages: list[BaseMessage]) -> GenerationMetrics:
    """Like generate(), but also captures token usage and wall-clock
    latency -- used by scripts/llm_cost_latency_check.py, not the hot
    request path. Does not use the response cache, since measuring a cache
    hit's near-zero latency/tokens would defeat the point.

    Token usage comes from the raw response's `usage_metadata` (present on
    real langchain-google-genai/langchain-groq responses); falls back to
    None fields if absent, e.g. against a mocked response in tests."""
    start = time.monotonic()
    response, text = _generate_raw(messages)
    elapsed = time.monotonic() - start

    usage = getattr(response, "usage_metadata", None) or {}

    return GenerationMetrics(
        text=text,
        input_tokens=usage.get("input_tokens"),
        output_tokens=usage.get("output_tokens"),
        total_tokens=usage.get("total_tokens"),
        latency_seconds=elapsed,
        provider="groq",
        model=settings.groq_model,
    )


if __name__ == "__main__":
    from app.rag.prompts import build_explanation_prompt

    sample_incident = {"host": "WIN10-ANALYST", "process": "powershell.exe", "user": "jdoe"}
    sample_chunks = [
        {
            "chunk_id": "T1059.001-mitre-0",
            "document": "Adversaries may abuse PowerShell commands and scripts for execution.",
            "metadata": {"technique_id": "T1059.001", "technique_name": "PowerShell"},
            "score": 0.81,
        }
    ]
    print(generate(build_explanation_prompt(sample_incident, sample_chunks)))
