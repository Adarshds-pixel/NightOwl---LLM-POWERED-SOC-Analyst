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

# pool_pre_ping: a connection that's gone stale (e.g. the Postgres
# container restarted while the backend process didn't) is tested with a
# lightweight SELECT 1 before being handed out, and transparently replaced
# if it's dead, instead of surfacing as a hard error on the next query that
# happens to draw it from the pool.
_is_sqlite = settings.database_url.startswith("sqlite")
engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
    # SQLite fallback only: wait up to 30 s for a writer instead of failing a
    # read with "database is locked" while a large upload is being stored.
    connect_args={"timeout": 30} if _is_sqlite else {},
)

if _is_sqlite:
    from sqlalchemy import event

    @event.listens_for(engine, "connect")
    def _sqlite_wal(dbapi_connection, _record):
        # WAL lets readers proceed while a writer holds the database.
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    except Exception:
        # An exception mid-request (a route/service raising, not caught
        # anywhere below this dependency) would otherwise leave whatever
        # was executed on this session's transaction uncommitted but also
        # not explicitly rolled back -- close() alone doesn't guarantee
        # which one happens. Rolling back explicitly here means the next
        # request that draws a fresh session always starts from clean,
        # known state regardless of what the failed request had queued.
        db.rollback()
        raise
    finally:
        db.close()
