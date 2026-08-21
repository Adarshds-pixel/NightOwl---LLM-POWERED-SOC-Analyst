"""Response cache for explain()/chat() results, keyed on incident id
(+ message, for chat) -- Day 13 production hardening. Closes the caching
gap `docs/decisions.md` already flagged at Day 8/11 but never implemented,
protecting the free-tier LLM quota from repeated identical explain/chat
calls (e.g. a user reopening the same incident, or a UI re-fetching on
remount).

Distinct from `rag/llm_client.py`'s cache (Day 12): that one is opt-in, off
by default, keyed on the *exact rendered prompt* -- a manual-testing aid.
This one is on by default, keyed on the *caller-facing* incident id (or
incident id + message), and sits one layer up (wired in at the route call
site around `explain_service.generate_explanation`/
`chat_service.generate_chat_reply`), so a hit also skips the retriever
call, not just the LLM call. The two caches coexist without conflict.

Entries expire after `settings.response_cache_ttl_seconds` so a stale
explanation/reply doesn't linger forever if an incident's underlying data
changes.
"""

import time
from threading import Lock

from app.core.config import settings

_explain_cache: dict[int, tuple[float, object]] = {}
_chat_cache: dict[tuple[int, str], tuple[float, object]] = {}
_lock = Lock()


def _is_expired(stored_at: float) -> bool:
    return time.monotonic() - stored_at > settings.response_cache_ttl_seconds


def get_explanation(incident_id: int):
    with _lock:
        entry = _explain_cache.get(incident_id)
        if entry is None:
            return None
        stored_at, result = entry
        if _is_expired(stored_at):
            del _explain_cache[incident_id]
            return None
        return result


def set_explanation(incident_id: int, result) -> None:
    with _lock:
        _explain_cache[incident_id] = (time.monotonic(), result)


def get_chat_reply(incident_id: int, message: str):
    key = (incident_id, message)
    with _lock:
        entry = _chat_cache.get(key)
        if entry is None:
            return None
        stored_at, result = entry
        if _is_expired(stored_at):
            del _chat_cache[key]
            return None
        return result


def set_chat_reply(incident_id: int, message: str, result) -> None:
    with _lock:
        _chat_cache[(incident_id, message)] = (time.monotonic(), result)


def clear() -> None:
    """Test-only: reset both caches (also used by conftest.py's autouse
    fixture, since autoincrement incident ids collide across test files
    against these process-lifetime dicts)."""
    with _lock:
        _explain_cache.clear()
        _chat_cache.clear()
