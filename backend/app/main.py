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

from fastapi import Depends, FastAPI
from starlette.middleware.cors import CORSMiddleware

from app.api.routes_ai_opinions import router as ai_opinions_router
from app.api.routes_alerts import router as alerts_router
from app.api.routes_chat import router as chat_router
from app.api.routes_demo import require_demo_mode
from app.api.routes_demo import router as demo_router
from app.api.routes_events import router as events_router
from app.api.routes_incidents import router as incidents_router
from app.api.routes_ingest import router as ingest_router
from app.api.routes_rules import router as rules_router
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
# Registered after the rate limiter -- Starlette's add_middleware prepends,
# so this ends up outermost, meaning CORS headers still attach to a 429/401
# response instead of the browser reporting those as an opaque CORS failure.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.cors_allow_origins.split(",") if o.strip()],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(ingest_router, dependencies=[Depends(require_api_key)])
app.include_router(mitre_router, dependencies=[Depends(require_api_key)])
app.include_router(incidents_router, dependencies=[Depends(require_api_key)])
app.include_router(chat_router, dependencies=[Depends(require_api_key)])
app.include_router(events_router, dependencies=[Depends(require_api_key)])
app.include_router(alerts_router, dependencies=[Depends(require_api_key)])
app.include_router(rules_router, dependencies=[Depends(require_api_key)])
app.include_router(demo_router, dependencies=[Depends(require_api_key), Depends(require_demo_mode)])
app.include_router(ai_opinions_router, dependencies=[Depends(require_api_key)])


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
