"""FastAPI application entrypoint.

The app instance, feature routers, and a health-check route. Day 6 mounted
the first feature routers (`api/routes_ingest.py`, `api/routes_mitre.py`);
Day 9 adds `api/routes_incidents.py`; later routers get added the same way.
"""

from fastapi import FastAPI

from app.api.routes_incidents import router as incidents_router
from app.api.routes_ingest import router as ingest_router
from app.api.routes_mitre import router as mitre_router
from app.core.config import settings

app = FastAPI(title=settings.app_name)
app.include_router(ingest_router)
app.include_router(mitre_router)
app.include_router(incidents_router)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
