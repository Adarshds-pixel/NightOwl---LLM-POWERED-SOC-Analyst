"""Day 13: limit/offset pagination on GET /incidents. No dedicated route
test for the list endpoint existed before this -- prior coverage was one
assertion inside tests/test_ingest_flow.py's end-to-end test.
"""

from datetime import datetime, timedelta, timezone

from app.models.incident import Incident

BASE_TIME = datetime(2026, 8, 19, 12, 0, 0, tzinfo=timezone.utc)


def _insert_incidents(SessionLocal, count: int) -> list[int]:
    ids = []
    with SessionLocal() as db:
        for i in range(count):
            incident = Incident(
                title=f"Incident {i}",
                status="open",
                severity="high",
                mitre_technique_ids=["T1059.001"],
                created_at=BASE_TIME + timedelta(hours=i),
                host=f"HOST-{i}",
            )
            db.add(incident)
            db.flush()
            ids.append(incident.id)
        db.commit()
    return ids


def test_default_limit_is_50(api_client):
    client, SessionLocal = api_client
    _insert_incidents(SessionLocal, 3)

    response = client.get("/incidents")

    assert response.status_code == 200
    body = response.json()
    assert body["limit"] == 50
    assert body["offset"] == 0
    assert body["count"] == 3
    assert body["total"] == 3


def test_total_reflects_full_match_count_beyond_one_page(api_client):
    client, SessionLocal = api_client
    _insert_incidents(SessionLocal, 60)

    response = client.get("/incidents")

    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 50  # default limit
    assert body["total"] == 60


def test_limit_and_offset_page_through_distinct_results(api_client):
    client, SessionLocal = api_client
    _insert_incidents(SessionLocal, 5)

    page1 = client.get("/incidents", params={"limit": 2, "offset": 0}).json()
    page2 = client.get("/incidents", params={"limit": 2, "offset": 2}).json()

    ids_page1 = [incident["id"] for incident in page1["incidents"]]
    ids_page2 = [incident["id"] for incident in page2["incidents"]]
    assert len(ids_page1) == 2
    assert len(ids_page2) == 2
    assert set(ids_page1).isdisjoint(ids_page2)
    assert page1["total"] == 5
    assert page2["total"] == 5


def test_limit_above_cap_returns_422(api_client):
    client, _ = api_client

    response = client.get("/incidents", params={"limit": 500})

    assert response.status_code == 422


def test_negative_offset_returns_422(api_client):
    client, _ = api_client

    response = client.get("/incidents", params={"offset": -1})

    assert response.status_code == 422
