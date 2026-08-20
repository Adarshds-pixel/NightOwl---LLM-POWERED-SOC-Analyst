
# from backend/, PYTHONIOENCODING=utf-8 ./venv/Scripts/python.exe, ad hoc:
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models.incident import Incident
import app.core.config as config_mod
import app.rag.llm_client as llm_client

engine = create_engine("sqlite+pysqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
Base.metadata.create_all(engine)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

def _override_get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = _override_get_db
client = TestClient(app, raise_server_exceptions=False)

with SessionLocal() as db:
    incident = Incident(title="Suspicious PowerShell execution on WIN10-ANALYST", status="open",
                         severity="high", mitre_technique_ids=["T1059.001"],
                         created_at=datetime.now(timezone.utc), host="WIN10-ANALYST")
    db.add(incident); db.commit(); db.refresh(incident)
    incident_id = incident.id

# 1-2: GET history edge cases (no LLM call)
print(client.get(f"/incidents/{incident_id}/chat").json())      # brand-new incident
print(client.get("/incidents/999999/chat").json())              # missing incident

# 3-4: 503-on-provider-failure (simulate by clearing the configured key)
orig_key = config_mod.settings.llm_api_key
config_mod.settings.llm_api_key = ""
print(client.post(f"/incidents/{incident_id}/explain").status_code)
print(client.post(f"/incidents/{incident_id}/chat", json={"message": "hi"}).status_code)
config_mod.settings.llm_api_key = orig_key

# 5-7: real end-to-end chat (Groq) -- 2 turns, then history
config_mod.settings.llm_provider = "groq"
llm_client._client = None
r1 = client.post(f"/incidents/{incident_id}/chat", json={"message": "Why was this flagged?"})
r2 = client.post(f"/incidents/{incident_id}/chat", json={"message": "What should I do first?"})
r3 = client.get(f"/incidents/{incident_id}/chat")
print(r1.status_code, len(r1.json()["sources"]))
print(r2.status_code)
print(r3.status_code, r3.json()["count"], [m["role"] for m in r3.json()["messages"]])


