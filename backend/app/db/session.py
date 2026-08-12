"""SQLAlchemy engine/session wiring + the FastAPI DB dependency.

`get_db` is a generator dependency: FastAPI calls it per-request, injects
the yielded Session into the route/service, and runs the `finally` block
(closing the session) once the request finishes — this is the standard
SQLAlchemy + FastAPI dependency-injection pattern, so routers never open
or close sessions themselves.
"""

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings

engine = create_engine(settings.database_url)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
