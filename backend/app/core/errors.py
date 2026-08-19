"""Consistent API error handling across routes (Day 12).

Two pieces:
  - `not_found()` -- one shared 404 helper so every route's "not found"
    response is worded identically (previously only explain_incident had
    one, phrased ad hoc).
  - `install_exception_handlers()` -- Starlette's default handler for an
    *unhandled* exception returns plain text, not JSON, which breaks every
    other route's contract of always responding with `{"detail": ...}`.
    This registers a handler so an unexpected bug still returns valid JSON
    (and gets logged) instead of a stack trace or a plain-text 500.
"""

import logging

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)


def not_found(entity: str, id_: object) -> HTTPException:
    return HTTPException(status_code=404, detail=f"{entity} {id_} not found")


def install_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(Exception)
    async def _unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("unhandled error on %s %s", request.method, request.url.path)
        return JSONResponse(status_code=500, content={"detail": "internal server error"})
