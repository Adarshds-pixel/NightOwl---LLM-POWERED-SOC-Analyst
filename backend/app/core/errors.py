"""Consistent API error handling across routes (Day 12).

Three pieces:
  - `not_found()` -- one shared 404 helper so every route's "not found"
    response is worded identically (previously only explain_incident had
    one, phrased ad hoc).
  - `install_exception_handlers()` registers:
      - a handler for `LLMProviderError` (Day 12) -- a known, expected
        upstream failure mode (missing key, timeout, rate limit, empty
        response), not a bug. Without this it fell through to the generic
        500 handler below with an unhelpful "internal server error"
        message, indistinguishable from an actual crash. Mapped to 503
        (upstream service unavailable) using the exception's own message,
        which is already descriptive (see rag/llm_client.py).
      - a handler for any other *unhandled* exception -- Starlette's
        default fallback for this returns plain text, not JSON, which
        breaks every other route's contract of always responding with
        `{"detail": ...}`. This registers a handler so an unexpected bug
        still returns valid JSON (and gets logged) instead of a stack
        trace or a plain-text 500.

`LLMProviderError` is imported locally inside `install_exception_handlers()`
rather than at module scope -- this module has no other imports from
feature code (app/rag, app/services, ...) and stays a leaf module other
code can import without pulling in the RAG stack; the local import mirrors
rag/explain_service.py's existing pattern of importing a sibling module's
symbol inside the one function that needs it.
"""

import logging

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)


def not_found(entity: str, id_: object) -> HTTPException:
    return HTTPException(status_code=404, detail=f"{entity} {id_} not found")


def install_exception_handlers(app: FastAPI) -> None:
    from app.rag.llm_client import LLMProviderError

    @app.exception_handler(LLMProviderError)
    async def _llm_provider_error_handler(request: Request, exc: LLMProviderError) -> JSONResponse:
        logger.warning("LLM provider error on %s %s: %s", request.method, request.url.path, exc)
        return JSONResponse(status_code=503, content={"detail": str(exc)})

    @app.exception_handler(Exception)
    async def _unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("unhandled error on %s %s", request.method, request.url.path)
        return JSONResponse(status_code=500, content={"detail": "internal server error"})
