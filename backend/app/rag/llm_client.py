"""LangChain-wired client for the free-tier LLM provider (Google Gemini).

Kept as a thin wrapper around ChatGoogleGenerativeAI, rather than importing
the SDK directly elsewhere, so:
  - the rest of the app (explain_service.py, Day 8+) never imports
    langchain_google_genai directly -- swapping providers later only
    touches this one file.
  - failures (missing key, quota, network) come back as one
    LLMProviderError instead of leaking provider-specific exceptions up
    through unrelated call sites.
"""

import logging
import time

from langchain_core.messages import BaseMessage
from langchain_google_genai import ChatGoogleGenerativeAI

from app.core.config import settings

logger = logging.getLogger(__name__)

_MAX_ATTEMPTS = 2  # one retry -- keep simple, this is a student project not a production SLA
_RETRY_DELAY_SECONDS = 2


class LLMProviderError(Exception):
    """Raised when the configured LLM provider can't produce a response
    (missing/invalid API key, network failure, rate limit, empty response)."""


_client: ChatGoogleGenerativeAI | None = None


def _extract_text(content) -> str:
    """Normalize an AIMessage's `content` into plain text.

    Current langchain-google-genai returns `content` as a list of content
    blocks (e.g. [{"type": "text", "text": ..., "extras": {...}}]) rather
    than a plain string -- confirmed via a real Gemini call during manual
    verification. Concatenate just the text blocks; a plain string response
    passes through unchanged.
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


def get_llm_client() -> ChatGoogleGenerativeAI:
    """Return a cached ChatGoogleGenerativeAI instance.

    Raises LLMProviderError immediately if no API key is configured, rather
    than waiting for the SDK to fail with an ambiguous auth error deep in a
    generate() call.
    """
    global _client
    if _client is not None:
        return _client

    if not settings.llm_api_key:
        raise LLMProviderError(
            "LLM_API_KEY is not set -- copy .env.example to .env and add a free "
            "Gemini API key from https://aistudio.google.com/apikey"
        )

    _client = ChatGoogleGenerativeAI(
        model=settings.llm_model,
        google_api_key=settings.llm_api_key,
    )
    return _client


def generate(messages: list[BaseMessage]) -> str:
    """Send `messages` (as produced by rag/prompts.py) to the LLM and return
    its text response, retrying once on transient failure."""
    client = get_llm_client()

    last_error: Exception | None = None
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        try:
            response = client.invoke(messages)
            text = _extract_text(getattr(response, "content", None))
            if not text:
                raise LLMProviderError("LLM returned an empty response")
            return text
        except Exception as exc:  # noqa: BLE001 -- deliberately broad: SDK can raise many types
            last_error = exc
            logger.warning("LLM call failed (attempt %d/%d): %s", attempt, _MAX_ATTEMPTS, exc)
            if attempt < _MAX_ATTEMPTS:
                time.sleep(_RETRY_DELAY_SECONDS)

    raise LLMProviderError(f"LLM call failed after {_MAX_ATTEMPTS} attempts: {last_error}") from last_error


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
