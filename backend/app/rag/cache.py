"""Response cache for explain()/chat() results, keyed on incident id
(+ message + a bounded-conversation-history fingerprint, for chat) --
Day 13 production hardening. Closes the caching gap `docs/decisions.md`
already flagged at Day 8/11 but never implemented, protecting the
free-tier LLM quota from repeated identical explain/chat calls (e.g. a
user reopening the same incident, or a UI re-fetching on remount). The
history fingerprint (added 2026-09-06) means the same question asked twice
in one incident only hits the cache if the conversation state leading up
to it is also the same -- otherwise a repeated question mid-conversation
would incorrectly return the first call's answer regardless of what was
said in between.

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

import hashlib
import json
import time
from threading import Lock

from app.core.config import settings
from app.rag.prompts import bound_chat_history

# Keys are whatever the caller passes as `incident_key`: in production the
# (incident_id, evidence fingerprint) tuple from
# incident_service.incident_cache_key, so new evidence or a demo reset (which
# recycles ids) can never be answered from a stale entry.
_explain_cache: dict[object, tuple[float, object]] = {}
# Keyed on (incident_id, message, history_fingerprint) -- the fingerprint
# is a hash of the *bounded* prior conversation (bound_chat_history(),
# shared with prompts.py's own history bound so the cache and the prompt
# agree on what "the same conversation state" means). Without it, two
# identical questions asked at different points in the same conversation
# (e.g. "why was this flagged?" as a sanity re-check after several more
# turns) would incorrectly hit the same cache entry and return the first
# call's answer regardless of what was said in between.
_chat_cache: dict[tuple[object, str, str], tuple[float, object]] = {}
_lock = Lock()


def _history_fingerprint(history: list[dict]) -> str:
    """A short, non-reversible fingerprint of the bounded conversation
    state -- deliberately not the raw history itself, so nothing sensitive
    from the conversation ends up embedded in a cache key that could be
    logged or inspected."""
    bounded = bound_chat_history(history)
    serialized = json.dumps(bounded, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16]


def _is_expired(stored_at: float) -> bool:
    return time.monotonic() - stored_at > settings.response_cache_ttl_seconds


MAX_CACHE_SIZE = 1000

def _prune_cache(cache: dict) -> None:
    if len(cache) <= MAX_CACHE_SIZE:
        return
    now = time.monotonic()
    ttl = settings.response_cache_ttl_seconds
    expired = [k for k, (stored_at, _) in cache.items() if now - stored_at > ttl]
    for k in expired:
        del cache[k]
    while len(cache) > MAX_CACHE_SIZE:
        try:
            del cache[next(iter(cache))]
        except StopIteration:
            break


def get_explanation(incident_id):
    with _lock:
        entry = _explain_cache.get(incident_id)
        if entry is None:
            return None
        stored_at, result = entry
        if _is_expired(stored_at):
            del _explain_cache[incident_id]
            return None
        # LRU bump
        del _explain_cache[incident_id]
        _explain_cache[incident_id] = entry
        return result


def set_explanation(incident_id, result) -> None:
    with _lock:
        if incident_id in _explain_cache:
            del _explain_cache[incident_id]
        _explain_cache[incident_id] = (time.monotonic(), result)
        _prune_cache(_explain_cache)


def get_chat_reply(incident_id, message: str, history: list[dict]):
    """`history` should be the same prior-turns list the caller is about to
    pass to generate_chat_reply() -- only the bounded tail of it actually
    affects the key (see _history_fingerprint), matching what the LLM
    prompt itself will see."""
    key = (incident_id, message, _history_fingerprint(history))
    with _lock:
        entry = _chat_cache.get(key)
        if entry is None:
            return None
        stored_at, result = entry
        if _is_expired(stored_at):
            del _chat_cache[key]
            return None
        # LRU bump
        del _chat_cache[key]
        _chat_cache[key] = entry
        return result


def set_chat_reply(incident_id, message: str, history: list[dict], result) -> None:
    key = (incident_id, message, _history_fingerprint(history))
    with _lock:
        if key in _chat_cache:
            del _chat_cache[key]
        _chat_cache[key] = (time.monotonic(), result)
        _prune_cache(_chat_cache)


def clear() -> None:
    """Drop every cached explanation and chat reply. Called by the demo reset
    (api/routes_demo.py) and by conftest.py's autouse fixture."""
    with _lock:
        _explain_cache.clear()
        _chat_cache.clear()
