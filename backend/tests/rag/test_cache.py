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
    assert cache.get_chat_reply(1, "What happened?") is None

    cache.set_chat_reply(1, "What happened?", "reply text")

    assert cache.get_chat_reply(1, "What happened?") == "reply text"


def test_chat_cache_is_keyed_per_message_not_just_incident():
    cache.set_chat_reply(1, "First question?", "first reply")

    assert cache.get_chat_reply(1, "Second question?") is None
    assert cache.get_chat_reply(1, "First question?") == "first reply"


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

    cache.set_chat_reply(1, "question", "stale reply")

    assert cache.get_chat_reply(1, "question") is None


def test_clear_resets_both_caches():
    cache.set_explanation(1, "explanation")
    cache.set_chat_reply(1, "message", "reply")

    cache.clear()

    assert cache.get_explanation(1) is None
    assert cache.get_chat_reply(1, "message") is None
