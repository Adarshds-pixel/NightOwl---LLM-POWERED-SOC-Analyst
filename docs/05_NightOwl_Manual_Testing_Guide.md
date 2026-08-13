# NightOwl Handbook — Volume 5: Manual Testing Guide

**Scope:** verifying everything built through **Pair 1 Day 3** (FastAPI skeleton, DB session dependency, DB models v1, Postgres/Alembic) and **Pair 2 Day 3–4** (ChromaDB + embeddings setup, MITRE ATT&CK loader, real knowledge-base build), as of **2026-08-12**.

This is a hands-on runbook, not the formal Testing Report (that template lives in Volume 3 §9.5 and is for the Day 20–21 Integration & Testing phase). Every step below was executed for real against this repo on 2026-08-12 and passed — see the "Last verified" line under each step.

---

## 0. Prerequisites

- Docker Desktop installed and running (`docker info` must succeed).
- `backend/venv` already has all deps from `backend/requirements.txt` installed. If starting from a fresh clone instead:
  ```
  cd backend
  python -m venv venv
  ./venv/Scripts/pip install -r requirements.txt
  ```
- Repo root `.env` must exist (copy from the template if missing):
  ```
  cp .env.example .env
  ```
- **Windows + corporate/AV network only:** if you hit `SSLError: CERTIFICATE_VERIFY_FAILED` when anything tries to reach GitHub/HuggingFace (this environment's default network intercepts TLS via a root CA that's trusted by Windows but not by Python's bundled `certifi`), install once per venv:
  ```
  ./venv/Scripts/python.exe -m pip install pip-system-certs
  ```
  This makes Python trust the same certificate store Windows/curl already trust. No app code changes needed — confirmed as the fix here.

---

## 1. Offline unit tests (no network, no DB)

```
cd backend
./venv/Scripts/python.exe -m pytest tests/test_day3_backend_setup.py tests/test_day3_models.py -v
```

Covers:
- `test_health_check` — FastAPI `/health` via `TestClient`.
- `test_models_register_expected_tables`, `test_models_create_all_against_sqlite` — all 5 SQLAlchemy models register and `create_all()` cleanly against in-memory SQLite.

**Expected:** `3 passed`.
**Last verified:** 2026-08-12 — 3 passed in 1.16s.

---

## 2. Network-dependent RAG/MITRE tests

```
cd backend
./venv/Scripts/python.exe -m pytest tests/test_day3_setup.py -v
```

Covers:
- `test_chroma_add_and_query` — ChromaDB `PersistentClient`, upsert + query round-trip.
- `test_embedding_shape` — `sentence-transformers` (`all-MiniLM-L6-v2`) produces a 384-dim vector.
- `test_mitre_loader_has_known_technique` — downloads/parses the official MITRE ATT&CK Enterprise STIX bundle (pinned to `ATT&CK-v19.2`), asserts 500+ techniques and that `T1059.001` ("PowerShell") is present.

Needs outbound internet (GitHub raw + HuggingFace Hub for model weights on first run — subsequent runs use local caches and are much faster).

**Expected:** `3 passed` (first run ~80–90s while the embedding model downloads; cached runs are seconds).
**Last verified:** 2026-08-12 — 3 passed in 84.61s.

---

## 3. Live Postgres + Alembic migration

```
cd <repo root>
docker compose up -d db
```

Wait for it to be healthy:
```
docker compose exec db pg_isready -U nightowl
```

Apply the migration:
```
cd backend
./venv/Scripts/python.exe -m alembic upgrade head
./venv/Scripts/python.exe -m alembic current   # should print: fa0ac08ab62f (head)
```

Verify the 5 core tables exist:
```
docker compose exec db psql -U nightowl -d nightowl -c "\dt"
```

**Expected:** `alembic_version`, `alerts`, `chat_messages`, `events`, `incidents`, `rules` — 6 tables.
**Last verified:** 2026-08-12 — all 6 tables present, `alembic current` = `fa0ac08ab62f (head)`. This was the first time the migration had been run against a live Postgres instance rather than only the in-memory SQLite used by tests.

---

## 4. Live FastAPI server smoke test

```
cd backend
./venv/Scripts/python.exe -m uvicorn app.main:app --port 8000
```
In another shell:
```
curl http://127.0.0.1:8000/health
```

**Expected:** `{"status":"ok"}`, HTTP 200.
**Last verified:** 2026-08-12 — confirmed `{"status":"ok"}` / HTTP 200 outside of the `TestClient` harness. Stop the server afterward (Ctrl+C, or on Windows find the PID with `netstat -ano | findstr :8000` and `taskkill /F /PID <pid>`).

---

## 5. Real knowledge-base build (Pair 2 Day 4 deliverable)

```
cd backend
./venv/Scripts/python.exe scripts/build_kb.py
```

Downloads/parses the MITRE dataset, chunks all non-deprecated/non-revoked techniques plus the 5 playbooks under `data/knowledge_base/playbooks/`, embeds them with the project's own `sentence-transformers` wrapper (not Chroma's default embedding function), and upserts into the `knowledge_base` Chroma collection.

**Expected:** a summary line like `MITRE techniques: N processed, M skipped (deprecated/revoked)`, `Playbooks: 5 processed`, and a final `Upserted <count> chunks into Chroma collection 'knowledge_base' (<count> total in collection)`.
**Last verified:** 2026-08-12 — 697 techniques processed, 161 skipped (deprecated/revoked), 5 playbooks processed, 1888 total chunks upserted.

---

## 6. Full regression pass

Once Postgres is up and the MITRE/embedding caches are warm:
```
cd backend
./venv/Scripts/python.exe -m pytest -v
```

**Expected:** all 6 tests pass together.
**Last verified:** 2026-08-12 — `6 passed in 35.64s`.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `failed to connect to the docker API ... dockerDesktopLinuxEngine` | Docker Desktop isn't running | Launch Docker Desktop and wait ~10–20s, then retry |
| `SSLError: CERTIFICATE_VERIFY_FAILED` on any GitHub/HuggingFace call | Corporate/AV TLS interception not trusted by Python's `certifi` bundle | `pip install pip-system-certs` in the venv (see Prerequisites) |
| `pg_isready` never succeeds / port 5433 already in use | Another Postgres instance already bound to 5433, or the container needs more time | `docker compose ps`, `docker compose logs db`; confirm nothing else owns host port 5433 |
| First run of `test_day3_setup.py` or `build_kb.py` is slow (~1–2 min) | `sentence-transformers`/`torch` downloading model weights and MITRE JSON on first use | Expected once; subsequent runs use local caches (`data/mitre/enterprise-attack.json`, HF cache, `data/chroma/`) |
| `uvicorn` port 8000 still bound after stopping | Reload/watcher spawned a child process with a different PID | `netstat -ano \| findstr :8000` then `taskkill /F /PID <pid>` |

---

## Out of scope for this guide

- Frontend testing (nothing built yet — Days 13+).
- Sigma detection engine, ingestion API, incident endpoints (Pair 1 Days 4–12 — not yet built).
- RAG retrieval/generation/chat endpoints (Pair 2 Days 5–12 — not yet built).
- The formal Testing Report (Volume 3 §9.5) — that's produced during Days 20–21 Integration & Testing, covering unit/integration/E2E coverage and RAG accuracy scoring across the whole system.
