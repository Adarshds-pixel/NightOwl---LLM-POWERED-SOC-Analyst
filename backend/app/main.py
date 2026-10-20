"""FastAPI application entrypoint.

The app instance, feature routers, and a health-check route. Day 6 mounted
the first feature routers (`api/routes_ingest.py`, `api/routes_mitre.py`);
Day 9 adds `api/routes_incidents.py`; Day 11 adds `api/routes_chat.py`; later
routers get added the same way. Day 12 wires structured logging + a
consistent unhandled-error handler. Day 14 adds CORS so the new Vite
frontend (`frontend/`) can call this API from the browser. `api/routes_events.py`
adds the raw event-timeline endpoint behind the new Logs page, and
`api/routes_rules.py` exposes the loaded detection rule set (read-only)
behind the Rules Engine page. `api/routes_alerts.py` adds the real
one-row-per-alert feed behind the Alerts page. `api/routes_demo.py` adds
POST /demo/reset (behind require_demo_mode in addition to the usual API key).
"""

import logging

from fastapi import Depends, FastAPI
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

from app.api.routes_ai_opinions import router as ai_opinions_router
from app.api.routes_alerts import router as alerts_router
from app.api.routes_auth import router as auth_router
from app.api.routes_chat import router as chat_router
from app.api.routes_demo import require_demo_mode
from app.api.routes_demo import router as demo_router
from app.api.routes_events import router as events_router
from app.api.routes_incidents import router as incidents_router
from app.api.routes_ingest import router as ingest_router
from app.api.routes_rules import router as rules_router
from app.api.routes_mitre import router as mitre_router
from app.api.routes_ml import router as ml_router
from app.api.routes_system import router as system_router
from app.core.auth import CSRF_HEADER, require_api_key, require_session_auth
from app.core.config import resolve_session_secret, settings, validate_production_settings
from app.core.errors import install_exception_handlers
from app.core.logging import configure_logging
from app.core.rate_limit import rate_limit_middleware
from app.core.security_middleware import csrf_middleware, unhandled_error_middleware
from app.core.upload_guard import UploadGuardMiddleware
from app.db.session import get_db

configure_logging()
validate_production_settings(settings)

# Interactive API docs are a schema disclosure; keep them for local dev only.
_docs = {} if settings.is_local else {"docs_url": None, "redoc_url": None, "openapi_url": None}
app = FastAPI(title=settings.app_name, **_docs)
install_exception_handlers(app)

# Starlette's add_middleware prepends, so the LAST one registered here is the
# OUTERMOST. Final order, outermost first:
#   CORS -> Session -> rate limit -> CSRF -> error-to-JSON -> upload guard -> app
# * CORS outermost so 401/403/429/500 responses still carry CORS headers.
# * Session before the upload guard and auth, which read scope["session"].
# * Upload guard innermost of the middlewares, right before routing, so it
#   rejects an unauthenticated or oversized POST /ingest before the body is
#   read (see core/upload_guard.py).
app.add_middleware(UploadGuardMiddleware)
app.middleware("http")(unhandled_error_middleware)
app.middleware("http")(csrf_middleware)
app.middleware("http")(rate_limit_middleware)
app.add_middleware(
    SessionMiddleware,
    secret_key=resolve_session_secret(settings),
    session_cookie="nightowl_session",
    max_age=settings.session_max_age_seconds,
    same_site="lax",
    https_only=not settings.is_local,
)
# allow_credentials=True is required for the browser to send/receive the
# session cookie; allow_origins therefore stays an explicit list, never "*".
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.cors_allow_origins.split(",") if o.strip()],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key", CSRF_HEADER],
)
app.include_router(auth_router)
app.include_router(ingest_router, dependencies=[Depends(require_api_key), Depends(require_session_auth)])
app.include_router(mitre_router, dependencies=[Depends(require_api_key), Depends(require_session_auth)])
app.include_router(incidents_router, dependencies=[Depends(require_api_key), Depends(require_session_auth)])
app.include_router(chat_router, dependencies=[Depends(require_api_key), Depends(require_session_auth)])
app.include_router(events_router, dependencies=[Depends(require_api_key), Depends(require_session_auth)])
app.include_router(alerts_router, dependencies=[Depends(require_api_key), Depends(require_session_auth)])
app.include_router(rules_router, dependencies=[Depends(require_api_key), Depends(require_session_auth)])
app.include_router(
    demo_router,
    dependencies=[Depends(require_api_key), Depends(require_session_auth), Depends(require_demo_mode)],
)
app.include_router(ai_opinions_router, dependencies=[Depends(require_api_key), Depends(require_session_auth)])
app.include_router(system_router, dependencies=[Depends(require_api_key), Depends(require_session_auth)])
app.include_router(ml_router, dependencies=[Depends(require_api_key), Depends(require_session_auth)])


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness: the process answers. Polled by the console's status dot."""
    return {"status": "ok"}


@app.get("/readyz")
def readiness(db: Session = Depends(get_db)) -> JSONResponse:
    """Readiness: the process can serve real requests, i.e. the database
    answers. Used by the container healthcheck, so the console waits for a
    working backend rather than a merely running one. Public and detail-free
    (19 Oct 2026 audit, F-06); component detail stays behind login at
    /system/status."""
    try:
        db.execute(text("SELECT 1"))
    except Exception:  # noqa: BLE001 -- any failure means "not ready"
        logging.getLogger(__name__).warning("readiness check failed: database unreachable", exc_info=True)
        return JSONResponse(status_code=503, content={"status": "unavailable"})
    return JSONResponse(content={"status": "ready"})
