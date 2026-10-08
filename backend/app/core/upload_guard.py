"""Reject bad POST /ingest requests before the multipart body is read.

FastAPI parses a multipart form before it runs any dependency, including
`require_session_auth` -- so without this, an unauthenticated client could make
the server spool an arbitrarily large upload to temp disk and only then get a
401, and a missing or forged Content-Length bypassed the size check entirely.

This pure ASGI middleware runs inside SessionMiddleware (it reads
scope["session"]) and, for POST /ingest and POST /ingest/async only:
  1. 401s unless the request carries a logged-in session cookie or the
     configured API key (the cheap claim check -- the full server-side
     session validation still runs in the route dependency);
  2. 411s without a Content-Length and 413s when it exceeds the cap;
  3. counts body bytes as they arrive and stops reading past the cap, so a
     body longer than its declared Content-Length cannot slip through.
"""

import hmac
import json

from app.core.config import settings

INGEST_PATHS = frozenset({"/ingest", "/ingest/async"})
# Multipart boundaries and part headers on top of the file itself.
MULTIPART_OVERHEAD_BYTES = 1024 * 1024


class _BodyTooLarge(Exception):
    pass


async def _send_json(send, status: int, detail: str) -> None:
    body = json.dumps({"detail": detail}).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
        }
    )
    await send({"type": "http.response.body", "body": body})


def _auth_overridden(scope) -> bool:
    from app.core.auth import require_session_auth

    app = scope.get("app")
    return bool(app is not None and require_session_auth in getattr(app, "dependency_overrides", {}))


class UploadGuardMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("method") != "POST" or scope.get("path") not in INGEST_PATHS:
            await self.app(scope, receive, send)
            return

        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        session = scope.get("session") or {}
        api_key = headers.get("x-api-key")
        key_ok = bool(settings.api_key) and api_key is not None and hmac.compare_digest(api_key, settings.api_key)
        if not (session.get("authenticated") or key_ok or _auth_overridden(scope)):
            await _send_json(send, 401, "Not authenticated")
            return

        limit = settings.max_upload_bytes + MULTIPART_OVERHEAD_BYTES
        raw_length = headers.get("content-length")
        if raw_length is None:
            await _send_json(send, 411, "Content-Length is required for uploads")
            return
        try:
            declared = int(raw_length)
        except ValueError:
            await _send_json(send, 400, "invalid Content-Length")
            return
        if declared > limit:
            await _send_json(
                send, 413, f"file too large: exceeds the {settings.max_upload_bytes}-byte limit"
            )
            return

        received = 0

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise _BodyTooLarge()
            return message

        response_started = False

        async def tracking_send(message):
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except _BodyTooLarge:
            if not response_started:
                await _send_json(send, 413, f"file too large: exceeds the {settings.max_upload_bytes}-byte limit")
