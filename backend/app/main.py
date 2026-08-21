"""FastAPI application entrypoint.

The app instance, feature routers, and a health-check route. Day 6 mounted
the first feature routers (`api/routes_ingest.py`, `api/routes_mitre.py`);
Day 9 adds `api/routes_incidents.py`; Day 11 adds `api/routes_chat.py`; later
routers get added the same way. Day 12 wires structured logging + a
consistent unhandled-error handler.
"""

from fastapi import Depends, FastAPI

from app.api.routes_chat import router as chat_router
from app.api.routes_incidents import router as incidents_router
from app.api.routes_ingest import router as ingest_router
from app.api.routes_mitre import router as mitre_router
from app.core.auth import require_api_key
from app.core.config import settings
from app.core.errors import install_exception_handlers
from app.core.logging import configure_logging
from app.core.rate_limit import rate_limit_middleware

configure_logging()

app = FastAPI(title=settings.app_name)
install_exception_handlers(app)
app.middleware("http")(rate_limit_middleware)
app.include_router(ingest_router, dependencies=[Depends(require_api_key)])
app.include_router(mitre_router, dependencies=[Depends(require_api_key)])
app.include_router(incidents_router, dependencies=[Depends(require_api_key)])
app.include_router(chat_router, dependencies=[Depends(require_api_key)])


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
