"""FastAPI application entrypoint.

Just the app instance + a health-check route for now. Feature routers
(`api/routes_ingest.py`, `api/routes_incidents.py`, ...) get mounted here
starting Day 6 once they exist.
"""

from fastapi import FastAPI

from app.core.config import settings

app = FastAPI(title=settings.app_name)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
