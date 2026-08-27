"""Day 12 verification (Pair 2): core/errors.py's exception handlers.

Builds a throwaway FastAPI app (not the real app.main:app) with two routes
that each raise a specific exception type, so the handler dispatch itself
is under test in isolation from any real route's business logic.
"""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.errors import install_exception_handlers
from app.rag.llm_client import LLMProviderError


def _build_app() -> FastAPI:
    app = FastAPI()
    install_exception_handlers(app)

    @app.get("/boom-llm")
    def boom_llm():
        raise LLMProviderError("provider unavailable: quota exceeded")

    @app.get("/boom-generic")
    def boom_generic():
        raise RuntimeError("unexpected bug")

    return app


def test_llm_provider_error_returns_503_with_message():
    client = TestClient(_build_app(), raise_server_exceptions=False)

    response = client.get("/boom-llm")

    assert response.status_code == 503
    assert response.json() == {"detail": "provider unavailable: quota exceeded"}


def test_unhandled_exception_still_returns_generic_500():
    client = TestClient(_build_app(), raise_server_exceptions=False)

    response = client.get("/boom-generic")

    assert response.status_code == 500
    assert response.json() == {"detail": "internal server error"}


def test_json_log_formatter_escapes_non_ascii():
    """A model response with typographic punctuation must not be able to make
    its own log line unwritable -- that turned /explain into a 500 on a
    Windows console (cp1252 stdout) until the formatter escaped non-ASCII."""
    import json
    import logging

    from app.core.logging import JsonFormatter

    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="encoded (base\u2011 64) command line \u2014 flagged",
        args=(),
        exc_info=None,
    )

    line = JsonFormatter().format(record)

    line.encode("cp1252")  # would raise before the fix
    assert json.loads(line)["message"].startswith("encoded (base")
