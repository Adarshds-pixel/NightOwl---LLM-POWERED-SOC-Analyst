"""Day 13: in-memory token-bucket rate limiting (app/core/rate_limit.py).

Uses a small configured capacity (via monkeypatch) so tests trip the limit
deterministically in a handful of requests, and rewinds `last_refill`
instead of sleeping to simulate elapsed time.
"""

import pytest

from app.core.config import settings
from app.core.rate_limit import _buckets


def test_within_capacity_all_succeed(api_client, monkeypatch):
    monkeypatch.setattr(settings, "rate_limit_per_minute", 3)
    client, _ = api_client

    for _ in range(3):
        assert client.get("/health").status_code == 200


def test_over_capacity_returns_429(api_client, monkeypatch):
    monkeypatch.setattr(settings, "rate_limit_per_minute", 3)
    client, _ = api_client

    for _ in range(3):
        assert client.get("/health").status_code == 200

    response = client.get("/health")
    assert response.status_code == 429
    assert response.json()["detail"] == "rate limit exceeded"


def test_bucket_refills_over_time(api_client, monkeypatch):
    monkeypatch.setattr(settings, "rate_limit_per_minute", 3)
    client, _ = api_client

    for _ in range(3):
        assert client.get("/health").status_code == 200
    assert client.get("/health").status_code == 429

    # capacity=3 refills at 3/60 = 0.05 tokens/sec, so refilling one full
    # token needs 20s of elapsed time -- rewind generously past that instead
    # of sleeping the suite for it.
    bucket = _buckets["testclient"]
    bucket.last_refill -= 25

    assert client.get("/health").status_code == 200


def test_zero_disables_rate_limiting(api_client, monkeypatch):
    monkeypatch.setattr(settings, "rate_limit_per_minute", 0)
    client, _ = api_client

    for _ in range(200):
        assert client.get("/health").status_code == 200


def test_buckets_start_empty_each_test():
    assert _buckets == {}
