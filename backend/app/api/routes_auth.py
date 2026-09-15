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
"""

import bcrypt
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from app.core.config import settings
from app.core.rate_limit import allow_login_attempt, get_client_ip

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


class SessionResponse(BaseModel):
    username: str


@router.post("/login", response_model=SessionResponse)
def login(payload: LoginRequest, request: Request) -> SessionResponse:
    # Keyed the same way the global rate limiter keys its own bucket
    # (client host) -- see allow_login_attempt's docstring for why this is
    # a separate, much smaller budget than ordinary API traffic.
    client_key = get_client_ip(request)
    if not allow_login_attempt(client_key):
        raise HTTPException(status_code=429, detail="Too many login attempts. Try again shortly.")

    # Every failure path returns the exact same status/detail, and takes
    # about the same amount of work either way (a real bcrypt.checkpw call
    # against a fixed dummy hash when the username doesn't match, rather
    # than short-circuiting) -- so neither the response body nor the
    # response time tells an attacker whether the username or the password
    # was the wrong part.
    _DUMMY_HASH = "$2b$12$C6UzMDM.H6dfI/f/IKcEeO0i.h/D6.aRV6a7ZQZzq6q1qz1qz1qzO"
    hash_to_check = settings.admin_password_hash if payload.username == settings.admin_username else _DUMMY_HASH
    password_ok = bool(settings.admin_password_hash) and bcrypt.checkpw(
        payload.password.encode("utf-8"), hash_to_check.encode("utf-8")
    )
    username_ok = payload.username == settings.admin_username

    if not (username_ok and password_ok):
        raise HTTPException(status_code=401, detail="Invalid credentials.")

    request.session.clear()
    request.session["authenticated"] = True
    request.session["username"] = settings.admin_username
    return SessionResponse(username=settings.admin_username)


@router.post("/logout")
def logout(request: Request) -> dict[str, bool]:
    # Idempotent on purpose: logging out of an already-expired or
    # never-authenticated session is not an error, it just confirms the
    # end state the caller wanted.
    request.session.clear()
    return {"ok": True}


@router.get("/me", response_model=SessionResponse)
def me(request: Request) -> SessionResponse:
    if not request.session.get("authenticated"):
        raise HTTPException(status_code=401, detail="Not authenticated")
    return SessionResponse(username=request.session.get("username", settings.admin_username))
