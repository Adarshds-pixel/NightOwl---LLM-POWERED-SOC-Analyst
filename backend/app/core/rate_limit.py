"""In-memory token-bucket rate limiting (Day 13).

Hand-rolled rather than pulling in slowapi -- consistent with the project's
stdlib-first, $0 policy (see logging.py's docstring for the same reasoning).
`rate_limit_per_minute <= 0` disables limiting entirely, the same "0/empty =
off" convention used for the other Day 13 settings.

`EXEMPT_PATHS` carves out the liveness probe: the frontend polls `/health`
on a timer to show whether the API is reachable, and spending an analyst's
request budget on that both starves the real requests and makes a throttled
API look like a *down* API in the UI. A liveness check is exactly the thing
that must still answer when everything else is being throttled.

`_buckets` is process-global state keyed by client host. Tests must reset it
between runs (see tests/conftest.py's `_reset_rate_limiter` autouse fixture) --
Starlette's TestClient reports every request's `request.client` as the same
fixed ("testclient", 50000) tuple, so without a reset, token consumption in
one test would leak into later, unrelated tests as spurious 429s.
"""

import ipaddress
import time
import threading
from dataclasses import dataclass

from fastapi import Request
from fastapi.responses import JSONResponse

from app.core.config import settings


@dataclass
class _TokenBucket:
    tokens: float
    last_refill: float


_buckets: dict[str, _TokenBucket] = {}

# A second, separate bucket store for login attempts specifically (see
# `allow_login_attempt` below) -- deliberately not the same dict as
# `_buckets`, so a burst of normal dashboard traffic from one host can never
# spend down the budget meant to slow down password guessing, or vice versa.
_login_buckets: dict[str, _TokenBucket] = {}

# Not rate limited (see module docstring). Kept as an exact-match set rather
# than a prefix check so a future "/healthz/expensive-subcheck" cannot slip
# through by accident.
EXEMPT_PATHS = frozenset({"/health", "/readyz"})
_rate_limit_lock = threading.Lock()


def reset_rate_limiter() -> None:
    with _rate_limit_lock:
        _buckets.clear()
        _login_buckets.clear()


MAX_BUCKETS = 10000

def _prune_buckets(buckets: dict[str, _TokenBucket]) -> None:
    # Caller must hold _rate_limit_lock
    if len(buckets) < MAX_BUCKETS:
        return
    now = time.monotonic()
    # A bucket is fully refilled (inactive) if 60 seconds have passed since last refill
    inactive = [k for k, b in buckets.items() if now - b.last_refill >= 60.0]
    for k in inactive:
        del buckets[k]

def _consume(buckets: dict[str, _TokenBucket], key: str, capacity: int) -> bool:
    if capacity <= 0:
        return True

    refill_per_sec = capacity / 60.0
    
    with _rate_limit_lock:
        now = time.monotonic()
        bucket = buckets.get(key)
        if bucket is None:
            if len(buckets) >= MAX_BUCKETS:
                _prune_buckets(buckets)
            
            if len(buckets) >= MAX_BUCKETS:
                # Cache is saturated with active buckets. Cannot evict without resetting 
                # their rate limits (fail open). Fail closed to prevent unbounded memory 
                # and unlimited requests.
                return False
                
            bucket = _TokenBucket(tokens=capacity, last_refill=now)
            buckets[key] = bucket
        else:
            # LRU bump
            del buckets[key]
            buckets[key] = bucket

        bucket.tokens = min(capacity, bucket.tokens + (now - bucket.last_refill) * refill_per_sec)
        bucket.last_refill = now

        if bucket.tokens < 1:
            return False
        bucket.tokens -= 1
        return True


def _allow(key: str) -> bool:
    return _consume(_buckets, key, settings.rate_limit_per_minute)


def allow_login_attempt(key: str) -> bool:
    """Whether this client may try to log in right now -- a peek, consuming
    nothing. Only *failed* attempts spend the budget (record_failed_login),
    so an admin logging in normally never throttles themselves."""
    capacity = settings.login_rate_limit_per_minute
    if capacity <= 0:
        return True
    with _rate_limit_lock:
        bucket = _login_buckets.get(key)
        if bucket is None:
            return True
        now = time.monotonic()
        tokens = min(capacity, bucket.tokens + (now - bucket.last_refill) * capacity / 60.0)
        return tokens >= 1


def record_failed_login(key: str) -> None:
    """Spend one token of the brute-force budget for POST /auth/login -- see
    `login_rate_limit_per_minute`'s docstring in config.py for why this is a
    separate, much smaller budget than ordinary API traffic."""
    _consume(_login_buckets, key, settings.login_rate_limit_per_minute)


def get_client_ip(request: Request) -> str:
    peer_ip = request.client.host if request.client else "unknown"

    trusted_proxies_str = getattr(settings, "trusted_proxies", "")
    if not trusted_proxies_str:
        return peer_ip

    trusted_networks = []
    for p in trusted_proxies_str.split(","):
        p = p.strip()
        if not p:
            continue
        try:
            trusted_networks.append(ipaddress.ip_network(p, strict=False))
        except ValueError:
            pass

    if not trusted_networks:
        return peer_ip

    try:
        peer_addr = ipaddress.ip_address(peer_ip)
    except ValueError:
        return peer_ip

    if not any(peer_addr in net for net in trusted_networks):
        return peer_ip

    forwarded_for = request.headers.get("X-Forwarded-For")
    if not forwarded_for:
        return peer_ip

    ips = [ip.strip() for ip in forwarded_for.split(",") if ip.strip()]
    if not ips:
        return peer_ip

    for ip_str in reversed(ips):
        try:
            addr = ipaddress.ip_address(ip_str)
            if not any(addr in net for net in trusted_networks):
                return ip_str
        except ValueError:
            return peer_ip

    return ips[0]


async def rate_limit_middleware(request: Request, call_next):
    if request.url.path in EXEMPT_PATHS:
        return await call_next(request)

    key = get_client_ip(request)
    if not _allow(key):
        return JSONResponse(status_code=429, content={"detail": "rate limit exceeded"})
    return await call_next(request)
