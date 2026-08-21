"""Shared-secret header auth (Day 13).

Empty `settings.api_key` (the default) disables enforcement entirely, the
same "empty string = not configured" convention already used for
`llm_api_key`/`groq_api_key` in config.py -- this keeps local dev, the
Postman collection, and the existing test suite working with no header
until an operator opts in by setting API_KEY in .env.
"""

from fastapi import Header, HTTPException

from app.core.config import settings


def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    if not settings.api_key:
        return
    if x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="invalid or missing API key")
