"""Day 3 verification (Pair 1): DB models v1 register correctly on Base.metadata.

Uses an in-memory SQLite engine (not Postgres) so this runs offline, the
same way Pair 2's Day 3 tests and test_day3_backend_setup.py do — no
docker-compose/Postgres dependency for the test suite itself (Alembic's
autogenerate step against real Postgres is verified separately, manually).
"""

from sqlalchemy import create_engine

from app.db.base import Base
from app.models import Alert, ChatMessage, Event, Incident, Rule  # noqa: F401


def test_models_register_expected_tables():
    expected = {"events", "alerts", "incidents", "rules", "chat_messages"}
    assert expected.issubset(Base.metadata.tables.keys())


def test_models_create_all_against_sqlite():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    with engine.connect() as conn:
        table_names = {
            row[0]
            for row in conn.exec_driver_sql(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
    assert {"events", "alerts", "incidents", "rules", "chat_messages"}.issubset(table_names)
