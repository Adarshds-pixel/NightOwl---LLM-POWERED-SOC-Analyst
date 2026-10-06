"""Admin login/logout/session-check -- the only three endpoints in the
single-admin authentication system. No registration, no roles, no password
reset: `settings.admin_username`/`admin_password_hash` are the one and only
credential, set once via environment configuration (see .env.example).

Deliberately NOT gated by `require_api_key`/`require_session_auth` at the
router level the way every other router is: `/auth/login` has to be
reachable by someone who is not yet authenticated (that is the whole
point), and `/auth/me` has to be callable to *find out* whether the caller
is authenticated rather than being blocked before it can answer. Each
endpoint below does its own, endpoint-appropriate check instead.

Each successful login creates an `admin_sessions` row (models/admin_session.py)
whose random id is stored in the signed cookie; logout revokes that row, so a
copied cookie stops working the moment the admin logs out.
"""

import logging
import secrets
from datetime import datetime, timedelta, timezone

import bcrypt
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import delete, or_
from sqlalchemy.orm import Session

from app.core.auth import session_is_valid
from app.core.config import settings
from app.core.rate_limit import allow_login_attempt, get_client_ip, record_failed_login
from app.db.session import get_db
from app.models.admin_session import AdminSession

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

# A valid bcrypt hash of a random string -- checked against when the username
# is wrong, so a wrong username costs the same bcrypt work as a wrong password.
_DUMMY_HASH = bcrypt.hashpw(secrets.token_bytes(16), bcrypt.gensalt()).decode("utf-8")

# bcrypt only looks at the first 72 bytes and bcrypt>=5 raises on longer input.
_BCRYPT_MAX_BYTES = 72


class LoginRequest(BaseModel):
    username: str = Field(max_length=255)
    password: str = Field(max_length=1024)


class SessionResponse(BaseModel):
    username: str


def _password_matches(password: str, hashed: str) -> bool:
    if not hashed:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8")[:_BCRYPT_MAX_BYTES], hashed.encode("utf-8"))
    except ValueError:
        # A malformed ADMIN_PASSWORD_HASH -- a configuration error, not the
        # caller's fault, but still not a 500 and never a successful login.
        logger.error("ADMIN_PASSWORD_HASH is not a valid bcrypt hash; login is impossible until it is fixed")
        return False


@router.post("/login", response_model=SessionResponse)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)) -> SessionResponse:
    client_key = get_client_ip(request)
    if not allow_login_attempt(client_key):
        raise HTTPException(status_code=429, detail="Too many failed login attempts. Try again shortly.")

    # Every failure path returns the exact same status/detail and costs the
    # same bcrypt work, so neither the body nor the timing says whether the
    # username or the password was wrong.
    username_ok = secrets.compare_digest(payload.username, settings.admin_username)
    hash_to_check = settings.admin_password_hash if username_ok else _DUMMY_HASH
    password_ok = _password_matches(payload.password, hash_to_check) and bool(settings.admin_password_hash)

    if not (username_ok and password_ok):
        record_failed_login(client_key)
        raise HTTPException(status_code=401, detail="Invalid credentials.")

    now = datetime.now(timezone.utc)
    # Housekeeping: drop rows nobody can use any more.
    db.execute(
        delete(AdminSession).where(or_(AdminSession.expires_at < now, AdminSession.revoked_at.is_not(None)))
    )
    sid = secrets.token_urlsafe(32)
    db.add(
        AdminSession(
            id=sid,
            username=settings.admin_username,
            created_at=now,
            expires_at=now + timedelta(seconds=settings.session_max_age_seconds),
        )
    )
    db.commit()

    request.session.clear()
    request.session["authenticated"] = True
    request.session["username"] = settings.admin_username
    request.session["sid"] = sid
    return SessionResponse(username=settings.admin_username)


@router.post("/logout")
def logout(request: Request, db: Session = Depends(get_db)) -> dict[str, bool]:
    # Idempotent on purpose: logging out of an already-expired or
    # never-authenticated session is not an error, it just confirms the
    # end state the caller wanted.
    sid = request.session.get("sid")
    if sid:
        row = db.get(AdminSession, sid)
        if row is not None and row.revoked_at is None:
            row.revoked_at = datetime.now(timezone.utc)
            db.commit()
    request.session.clear()
    return {"ok": True}


@router.get("/me", response_model=SessionResponse)
def me(request: Request, db: Session = Depends(get_db)) -> SessionResponse:
    if not request.session.get("authenticated") or not session_is_valid(db, request.session.get("sid")):
        raise HTTPException(status_code=401, detail="Not authenticated")
    return SessionResponse(username=request.session.get("username", settings.admin_username))
