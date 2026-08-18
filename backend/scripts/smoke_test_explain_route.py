"""Day 9 manual smoke test: real FastAPI route + real retrieval + real Gemini
calls (nothing mocked) for POST /incidents/{id}/explain.

Run for real from backend/: `python scripts/smoke_test_explain_route.py`
Requires a real LLM_API_KEY in .env (see rag/llm_client.py).

Substitutes an in-memory SQLite DB for Postgres via the same
`dependency_overrides[get_db]` pattern the automated route tests use --
this environment doesn't have Docker/Postgres available, so this is the
closest thing to a true end-to-end check of the route's own logic
(incident lookup, _incident_to_dict, response building) short of standing
up the real docker-compose stack (see docs/05_..._Manual_Testing_Guide.md
Troubleshooting table).
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # backend/

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app.db.base import Base  # noqa: E402
from app.db.session import get_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models.incident import Incident  # noqa: E402

engine = create_engine(
    "sqlite+pysqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
Base.metadata.create_all(engine)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


def _override_get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = _override_get_db
client = TestClient(app)

with SessionLocal() as db:
    incident = Incident(
        title="Suspicious PowerShell execution on WIN10-ANALYST",
        status="open",
        severity="high",
        mitre_technique_ids=["T1059.001"],
        created_at=datetime.now(timezone.utc),
        host="WIN10-ANALYST",
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)
    incident_id = incident.id

print(f"Inserted test incident id={incident_id}")

response = client.post(f"/incidents/{incident_id}/explain")
print(f"\nHTTP {response.status_code}\n")
print(json.dumps(response.json(), indent=2))
