"""Shared-secret header auth (Day 13), plus the admin login session guard
added alongside it (see api/routes_auth.py for the login/logout/me
endpoints that actually populate the session). These are two independent
mechanisms that both happen to live in this module: `require_api_key` is a
coarse, all-or-nothing deployment-level gate (still off by default, still
untouched by the login work); `require_session_auth` is the real per-request
check that a route is being called by someone who has actually logged in.
Routers apply both as separate dependencies rather than one replacing the
other.

Empty `settings.api_key` (the default) disables `require_api_key`
enforcement entirely, the same "empty string = not configured" convention
already used for `groq_api_key` in config.py -- this keeps local dev, the
Postman collection, and the existing test suite working with no header
until an operator opts in by setting API_KEY in .env.
"""

from fastapi import Header, HTTPException, Request

from app.core.config import settings


def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    if not settings.api_key:
        return
    if x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="invalid or missing API key")


def require_session_auth(request: Request) -> None:
    """Gates every real application route behind a logged-in admin session.
    `request.session` is populated by Starlette's SessionMiddleware (see
    main.py) from a signed, HttpOnly cookie -- there is no server-side
    session store to check against, the signature and `max_age` on the
    cookie itself are the only state. A request with no cookie, an expired
    cookie, or one that fails signature verification simply has an empty
    session dict here, so this one check covers "never logged in", "logged
    out", and "session expired" identically.
    """
    if not request.session.get("authenticated"):
        raise HTTPException(status_code=401, detail="Not authenticated")
