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


class MockRequest:
    def __init__(self, host, headers=None):
        class Client:
            pass
        self.client = Client()
        self.client.host = host
        self.headers = headers or {}


def test_proxy_direct_client(monkeypatch):
    from app.core.rate_limit import get_client_ip
    monkeypatch.setattr(settings, "trusted_proxies", "10.0.0.0/8")
    
    req = MockRequest("203.0.113.5", {"X-Forwarded-For": "192.168.1.5"})
    assert get_client_ip(req) == "203.0.113.5"


def test_proxy_trusted_proxy(monkeypatch):
    from app.core.rate_limit import get_client_ip
    monkeypatch.setattr(settings, "trusted_proxies", "10.0.0.0/8")
    
    req = MockRequest("10.0.0.5", {"X-Forwarded-For": "203.0.113.5"})
    assert get_client_ip(req) == "203.0.113.5"


def test_proxy_untrusted_proxy(monkeypatch):
    from app.core.rate_limit import get_client_ip
    monkeypatch.setattr(settings, "trusted_proxies", "10.0.0.0/8")
    
    req = MockRequest("192.168.1.1", {"X-Forwarded-For": "203.0.113.5"})
    assert get_client_ip(req) == "192.168.1.1"


def test_proxy_spoofed_xff(monkeypatch):
    from app.core.rate_limit import get_client_ip
    monkeypatch.setattr(settings, "trusted_proxies", "10.0.0.0/8")
    
    # Attacker tries to pretend they are 1.1.1.1, passing through trusted 10.0.0.5
    # Since the request comes from untrusted 203.0.113.5, XFF is ignored
    req = MockRequest("203.0.113.5", {"X-Forwarded-For": "1.1.1.1, 10.0.0.5"})
    assert get_client_ip(req) == "203.0.113.5"

    # Attacker is 203.0.113.5, proxy is 10.0.0.5
    # The XFF chain is "spoofed_ip, 203.0.113.5". We look from right to left.
    # 203.0.113.5 is not trusted, so it becomes the resolved client IP.
    req2 = MockRequest("10.0.0.5", {"X-Forwarded-For": "1.1.1.1, 203.0.113.5"})
    assert get_client_ip(req2) == "203.0.113.5"


def test_proxy_multiple_clients(monkeypatch):
    from app.core.rate_limit import get_client_ip, _allow, reset_rate_limiter
    monkeypatch.setattr(settings, "trusted_proxies", "10.0.0.0/8")
    monkeypatch.setattr(settings, "rate_limit_per_minute", 3)
    reset_rate_limiter()
    
    req1 = MockRequest("10.0.0.5", {"X-Forwarded-For": "203.0.113.1"})
    req2 = MockRequest("10.0.0.5", {"X-Forwarded-For": "203.0.113.2"})
    
    key1 = get_client_ip(req1)
    key2 = get_client_ip(req2)
    
    assert key1 == "203.0.113.1"
    assert key2 == "203.0.113.2"
    
    # Should be independent buckets
    for _ in range(3):
        assert _allow(key1) is True
    assert _allow(key1) is False
    
    assert _allow(key2) is True


def test_proxy_same_client(monkeypatch):
    from app.core.rate_limit import get_client_ip, _allow, reset_rate_limiter
    monkeypatch.setattr(settings, "trusted_proxies", "10.0.0.0/8")
    monkeypatch.setattr(settings, "rate_limit_per_minute", 3)
    reset_rate_limiter()
    
    req1 = MockRequest("10.0.0.5", {"X-Forwarded-For": "203.0.113.1"})
    req2 = MockRequest("10.0.0.6", {"X-Forwarded-For": "203.0.113.1"})
    
    key1 = get_client_ip(req1)
    key2 = get_client_ip(req2)
    
    assert key1 == "203.0.113.1"
    assert key2 == "203.0.113.1"
    
    for _ in range(3):
        assert _allow(key1) is True
    assert _allow(key2) is False


def test_proxy_malformed_xff(monkeypatch):
    from app.core.rate_limit import get_client_ip
    monkeypatch.setattr(settings, "trusted_proxies", "10.0.0.0/8")
    
    # Attacker connects through a trusted proxy but sends a malformed IP
    # in the X-Forwarded-For header. The rate limiter should fail safely
    # and use the peer IP (the proxy) rather than trusting the malformed string.
    req = MockRequest("10.0.0.5", {"X-Forwarded-For": "malformed_string, 10.0.0.6"})
    assert get_client_ip(req) == "10.0.0.5"

def test_rate_limit_bounded_buckets(monkeypatch):
    from app.core.rate_limit import _allow, _buckets, reset_rate_limiter
    import app.core.rate_limit as rate_limit
    monkeypatch.setattr(settings, "rate_limit_per_minute", 3)
    monkeypatch.setattr(rate_limit, "MAX_BUCKETS", 3)
    reset_rate_limiter()
    
    _allow("ip1")
    _allow("ip2")
    _allow("ip3")
    
    # ip4 should be rejected because the cache is full of active buckets
    assert _allow("ip4") is False
    
    assert len(_buckets) == 3
    assert "ip1" in _buckets
    assert "ip2" in _buckets
    assert "ip3" in _buckets
    assert "ip4" not in _buckets

def test_rate_limit_prunes_inactive(monkeypatch):
    from app.core.rate_limit import _allow, _buckets, reset_rate_limiter, time
    import app.core.rate_limit as rate_limit
    monkeypatch.setattr(settings, "rate_limit_per_minute", 3)
    monkeypatch.setattr(rate_limit, "MAX_BUCKETS", 3)
    reset_rate_limiter()
    
    _allow("ip1")
    _allow("ip2")
    _allow("ip3")
    
    # Simulate ip1 and ip2 being inactive for over 60 seconds
    _buckets["ip1"].last_refill -= 61.0
    _buckets["ip2"].last_refill -= 61.0
    
    # Now ip4 should be allowed because inactive buckets will be pruned
    assert _allow("ip4") is True
    
    assert len(_buckets) == 2
    assert "ip1" not in _buckets
    assert "ip2" not in _buckets
    assert "ip3" in _buckets
    assert "ip4" in _buckets
