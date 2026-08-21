"""In-memory token-bucket rate limiting (Day 13).

Hand-rolled rather than pulling in slowapi -- consistent with the project's
stdlib-first, $0 policy (see logging.py's docstring for the same reasoning).
`rate_limit_per_minute <= 0` disables limiting entirely, the same "0/empty =
off" convention used for the other Day 13 settings.

`_buckets` is process-global state keyed by client host. Tests must reset it
between runs (see tests/conftest.py's `_reset_rate_limiter` autouse fixture) --
Starlette's TestClient reports every request's `request.client` as the same
fixed ("testclient", 50000) tuple, so without a reset, token consumption in
one test would leak into later, unrelated tests as spurious 429s.
"""

import time
from dataclasses import dataclass

from fastapi import Request
from fastapi.responses import JSONResponse

from app.core.config import settings


@dataclass
class _TokenBucket:
    tokens: float
    last_refill: float


_buckets: dict[str, _TokenBucket] = {}


def reset_rate_limiter() -> None:
    _buckets.clear()


def _allow(key: str) -> bool:
    capacity = settings.rate_limit_per_minute
    if capacity <= 0:
        return True

    refill_per_sec = capacity / 60.0
    now = time.monotonic()
    bucket = _buckets.setdefault(key, _TokenBucket(tokens=capacity, last_refill=now))
    bucket.tokens = min(capacity, bucket.tokens + (now - bucket.last_refill) * refill_per_sec)
    bucket.last_refill = now

    if bucket.tokens < 1:
        return False
    bucket.tokens -= 1
    return True


async def rate_limit_middleware(request: Request, call_next):
    key = request.client.host if request.client else "unknown"
    if not _allow(key):
        return JSONResponse(status_code=429, content={"detail": "rate limit exceeded"})
    return await call_next(request)
