"""Day 13: in-memory token-bucket rate limiting (app/core/rate_limit.py).

Uses a small configured capacity (via monkeypatch) so tests trip the limit
deterministically in a handful of requests, and rewinds `last_refill`
instead of sleeping to simulate elapsed time.

These exercise `/incidents` rather than `/health`: `/health` is deliberately
exempt from limiting (it is the liveness probe the frontend polls), which
`test_health_is_exempt_from_rate_limiting` below pins down.
"""

import pytest

from app.core.config import settings
from app.core.rate_limit import _buckets


def test_within_capacity_all_succeed(api_client, monkeypatch):
    monkeypatch.setattr(settings, "rate_limit_per_minute", 3)
    client, _ = api_client

    for _ in range(3):
        assert client.get("/incidents").status_code == 200


def test_over_capacity_returns_429(api_client, monkeypatch):
    monkeypatch.setattr(settings, "rate_limit_per_minute", 3)
    client, _ = api_client

    for _ in range(3):
        assert client.get("/incidents").status_code == 200

    response = client.get("/incidents")
    assert response.status_code == 429
    assert response.json()["detail"] == "rate limit exceeded"


def test_bucket_refills_over_time(api_client, monkeypatch):
    monkeypatch.setattr(settings, "rate_limit_per_minute", 3)
    client, _ = api_client

    for _ in range(3):
        assert client.get("/incidents").status_code == 200
    assert client.get("/incidents").status_code == 429

    # capacity=3 refills at 3/60 = 0.05 tokens/sec, so refilling one full
    # token needs 20s of elapsed time -- rewind generously past that instead
    # of sleeping the suite for it.
    bucket = _buckets["testclient"]
    bucket.last_refill -= 25

    assert client.get("/incidents").status_code == 200


def test_zero_disables_rate_limiting(api_client, monkeypatch):
    monkeypatch.setattr(settings, "rate_limit_per_minute", 0)
    client, _ = api_client

    for _ in range(200):
        assert client.get("/incidents").status_code == 200


def test_health_is_exempt_from_rate_limiting(api_client, monkeypatch):
    """The frontend polls /health on a timer to tell "API is down" apart from
    "API is busy". If the probe itself could be throttled, a throttled API
    would look like an unreachable one -- and the probe would be competing
    with the very requests it is reporting on."""
    monkeypatch.setattr(settings, "rate_limit_per_minute", 3)
    client, _ = api_client

    for _ in range(50):
        assert client.get("/health").status_code == 200

    # ...and the exempt requests consumed no tokens, so a limited route still
    # has its full capacity available.
    for _ in range(3):
        assert client.get("/incidents").status_code == 200
    assert client.get("/incidents").status_code == 429


def test_buckets_start_empty_each_test():
    assert _buckets == {}
