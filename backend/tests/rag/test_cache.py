"""Day 13 verification (Pair 2): rag/cache.py's in-memory explain()/chat()
response cache -- keyed on incident id (+ message, for chat), distinct from
llm_client.py's opt-in exact-prompt cache (Day 12).
"""

from app.rag import cache


def setup_function():
    cache.clear()


def teardown_function():
    cache.clear()


def test_explanation_cache_roundtrip():
    assert cache.get_explanation(1) is None

    cache.set_explanation(1, "cached explanation result")

    assert cache.get_explanation(1) == "cached explanation result"


def test_explanation_cache_is_keyed_per_incident():
    cache.set_explanation(1, "result for incident 1")
    cache.set_explanation(2, "result for incident 2")

    assert cache.get_explanation(1) == "result for incident 1"
    assert cache.get_explanation(2) == "result for incident 2"


def test_chat_cache_roundtrip():
    assert cache.get_chat_reply(1, "What happened?", []) is None

    cache.set_chat_reply(1, "What happened?", [], "reply text")

    assert cache.get_chat_reply(1, "What happened?", []) == "reply text"


def test_chat_cache_is_keyed_per_message_not_just_incident():
    cache.set_chat_reply(1, "First question?", [], "first reply")

    assert cache.get_chat_reply(1, "Second question?", []) is None
    assert cache.get_chat_reply(1, "First question?", []) == "first reply"


def test_chat_cache_is_keyed_per_history_fingerprint_not_just_message():
    """The bug this closes: the same question asked at two different points
    in a conversation must not share a cache entry -- otherwise a repeated
    question mid-conversation would return the first call's answer,
    ignoring every turn that happened in between."""
    history_a = [{"role": "user", "content": "what happened?"}, {"role": "assistant", "content": "X happened."}]
    history_b = [{"role": "user", "content": "something else?"}, {"role": "assistant", "content": "Y."}]

    cache.set_chat_reply(1, "follow-up question?", history_a, "reply grounded in history A")

    assert cache.get_chat_reply(1, "follow-up question?", history_b) is None
    assert cache.get_chat_reply(1, "follow-up question?", history_a) == "reply grounded in history A"
    # Same conversation state, no history at all, is also its own key --
    # not conflated with either populated-history case above.
    assert cache.get_chat_reply(1, "follow-up question?", []) is None


def test_chat_cache_history_fingerprint_only_considers_the_bounded_tail():
    """Two histories that differ only outside the MAX_CHAT_HISTORY_MESSAGES
    window (i.e. differ only in turns bound_chat_history() would drop
    anyway) must fingerprint identically -- the cache key should agree with
    exactly what the LLM prompt itself will see, not the full raw history."""
    from app.rag.prompts import MAX_CHAT_HISTORY_MESSAGES

    tail = [{"role": "user", "content": f"turn {i}"} for i in range(MAX_CHAT_HISTORY_MESSAGES)]
    history_with_old_a = [{"role": "user", "content": "ancient turn A"}] + tail
    history_with_old_b = [{"role": "user", "content": "ancient turn B"}] + tail

    cache.set_chat_reply(1, "q?", history_with_old_a, "reply")

    assert cache.get_chat_reply(1, "q?", history_with_old_b) == "reply"


def test_explanation_cache_expires_after_ttl(monkeypatch):
    times = iter([100.0, 200.0])
    monkeypatch.setattr(cache.time, "monotonic", lambda: next(times))
    monkeypatch.setattr(cache.settings, "response_cache_ttl_seconds", 50.0)

    cache.set_explanation(1, "stale result")

    assert cache.get_explanation(1) is None


def test_chat_cache_expires_after_ttl(monkeypatch):
    times = iter([100.0, 200.0])
    monkeypatch.setattr(cache.time, "monotonic", lambda: next(times))
    monkeypatch.setattr(cache.settings, "response_cache_ttl_seconds", 50.0)

    cache.set_chat_reply(1, "question", [], "stale reply")

    assert cache.get_chat_reply(1, "question", []) is None


def test_clear_resets_both_caches():
    cache.set_explanation(1, "explanation")
    cache.set_chat_reply(1, "message", [], "reply")

    cache.clear()

    assert cache.get_explanation(1) is None
    assert cache.get_chat_reply(1, "message", []) is None

def test_cache_bounded_size(monkeypatch):
    monkeypatch.setattr(cache, "MAX_CACHE_SIZE", 3)
    
    cache.set_explanation(1, "res1")
    cache.set_explanation(2, "res2")
    cache.set_explanation(3, "res3")
    cache.set_explanation(4, "res4")
    
    assert len(cache._explain_cache) == 3
    assert cache.get_explanation(1) is None
    assert cache.get_explanation(2) == "res2"
    assert cache.get_explanation(3) == "res3"
    assert cache.get_explanation(4) == "res4"

def test_cache_lru_bump(monkeypatch):
    monkeypatch.setattr(cache, "MAX_CACHE_SIZE", 3)
    
    cache.set_explanation(1, "res1")
    cache.set_explanation(2, "res2")
    cache.set_explanation(3, "res3")
    
    # Bump 1
    cache.get_explanation(1)
    
    cache.set_explanation(4, "res4")
    
    assert cache.get_explanation(2) is None
    assert cache.get_explanation(1) == "res1"
    assert cache.get_explanation(3) == "res3"
    assert cache.get_explanation(4) == "res4"
