"""Request authentication: the admin login session, an optional API key for
headless clients, and the CSRF header check.

* `require_session_auth` is the real gate on every application route. A
  request passes with either
    - a signed session cookie whose server-side `admin_sessions` row exists,
      is unexpired and has not been revoked (see routes_auth.py), or
    - when `settings.api_key` is configured, a matching `X-API-Key` header.
      This is for scripts/Postman only; the browser frontend never holds the
      key (a key baked into a static JS bundle is public).
* `require_api_key` is kept as a separate router dependency for backward
  compatibility: when an API key is configured, a request with neither a
  logged-in session nor the key is rejected even if session auth is
  overridden (tests do that).
* `CSRF_HEADER` -- every state-changing request must carry it. A custom
  header cannot be sent cross-origin without a CORS preflight, which the
  CORS allow-list refuses, so a page on another origin (or another
  localhost port, which SameSite=Lax treats as same-site) cannot forge a
  POST /ingest or POST /demo/reset with the admin's cookie.
"""

import hmac
from datetime import datetime, timezone

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db

CSRF_HEADER = "X-NightOwl-Request"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def _api_key_matches(provided: str | None) -> bool:
    return bool(settings.api_key) and provided is not None and hmac.compare_digest(provided, settings.api_key)


def _session_claims(request: Request) -> tuple[bool, str | None]:
    session = request.scope.get("session") or {}
    return bool(session.get("authenticated")), session.get("sid")


def require_api_key(
    request: Request, x_api_key: str | None = Header(default=None, alias="X-API-Key")
) -> None:
    if not settings.api_key:
        return
    authenticated, _sid = _session_claims(request)
    if authenticated or _api_key_matches(x_api_key):
        return
    raise HTTPException(status_code=401, detail="invalid or missing API key")


def session_is_valid(db: Session, sid: str | None) -> bool:
    from app.models.admin_session import AdminSession

    if not sid:
        return False
    row = db.get(AdminSession, sid)
    if row is None or row.revoked_at is not None:
        return False
    expires_at = row.expires_at
    if expires_at.tzinfo is None:  # SQLite drops tzinfo
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return expires_at > datetime.now(timezone.utc)


def require_session_auth(request: Request, db: Session = Depends(get_db)) -> None:
    if _api_key_matches(request.headers.get("X-API-Key")):
        return
    authenticated, sid = _session_claims(request)
    if not authenticated or not session_is_valid(db, sid):
        raise HTTPException(status_code=401, detail="Not authenticated")


def session_actor(request: Request) -> str:
    """The audit-log actor for this request -- taken from the server-side
    session, never from a client-supplied field."""
    session = request.scope.get("session") or {}
    if session.get("authenticated") and session.get("username"):
        return str(session["username"])
    if _api_key_matches(request.headers.get("X-API-Key")):
        return "api-key"
    return "system"


def csrf_violation(method: str, headers) -> bool:
    return method.upper() not in SAFE_METHODS and not headers.get(CSRF_HEADER)
