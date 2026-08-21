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
