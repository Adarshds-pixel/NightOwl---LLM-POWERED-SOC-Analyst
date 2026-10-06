"""Two small HTTP middlewares registered in main.py.

* `csrf_middleware` -- rejects state-changing requests that lack the custom
  `X-NightOwl-Request` header (see core/auth.py for why that defeats CSRF).
* `unhandled_error_middleware` -- turns any uncaught exception into the
  project's usual `{"detail": ...}` JSON 500 *inside* the CORS middleware.
  The app-level `Exception` handler alone runs in Starlette's outermost
  ServerErrorMiddleware, i.e. outside CORS, so the browser saw a 500 as an
  opaque CORS failure and the frontend could never show the real message.
"""

import logging

from fastapi import Request
from fastapi.responses import JSONResponse

from app.core.auth import CSRF_HEADER, csrf_violation

logger = logging.getLogger(__name__)


async def csrf_middleware(request: Request, call_next):
    if csrf_violation(request.method, request.headers):
        return JSONResponse(status_code=403, content={"detail": f"missing {CSRF_HEADER} header"})
    return await call_next(request)


async def unhandled_error_middleware(request: Request, call_next):
    try:
        return await call_next(request)
    except Exception:
        logger.exception("unhandled error on %s %s", request.method, request.url.path)
        return JSONResponse(status_code=500, content={"detail": "internal server error"})
