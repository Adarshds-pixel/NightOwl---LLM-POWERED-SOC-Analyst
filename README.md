# NightOwl — AI-Powered Security Operations Center

NightOwl turns raw Windows Sysmon/EVTX telemetry into a small number of prioritized, explained incidents. It applies Sigma-style detection rules mapped to MITRE ATT&CK techniques, enriches each match with a Retrieval-Augmented Generation (RAG) LLM layer, and surfaces everything in a React SOC console — so a junior analyst can go from "Event ID 1, `powershell -enc ...`" to "this is obfuscated PowerShell execution (T1059.001) — isolate the host, capture memory, check the parent process chain" without needing years of SOC experience.

This is a final-year major project built by a team of 4, AI-assisted, over a 30-day roadmap.

## Features
- Batch ingestion of Sysmon EVTX log files
- Rule-based detection engine (45 Sigma-style YAML rules + a 3-pattern behavioral sequence engine, `pySigma`-validated) across Sysmon, Security, and PowerShell/Operational channels
- Automatic MITRE ATT&CK technique mapping + severity scoring
- Incident grouping, status workflow, and a backend audit trail
- RAG pipeline (ChromaDB + LangChain + LLM) generating grounded, plain-English incident explanations and recommended responses
- **Self-critique reasoning chain** — the LLM checks its own draft explanation against the retrieved sources before returning it, instead of a single-shot prompt
- **Source-attribution UI** — every explanation shows the exact knowledge-base chunks + similarity scores it was grounded in
- **Real admin authentication** — single-admin login, backend-enforced signed session cookie, no accounts/roles beyond the one operator
- SOC console: overview dashboard, incident queue and investigation view, AI assistant, MITRE ATT&CK coverage, alerts, log explorer, rules engine, reports and settings
- Demo Mode: one-click, real ingest → explain → chat walkthrough against a rotating real-world attack sample
- Runs entirely on **free-tier tools** (Groq free tier for the LLM; everything else is open-source/self-hosted) — **$0 to build and run**

## Repository structure

Three layers, one directory each.

```
├── backend/        FastAPI service: API routes, detection engine, ingestion,
│                   MITRE mapping, incident/severity services, DB models,
│                   Alembic migrations, tests, and EVTX sample_logs
├── frontend/       React + Vite + Tailwind SOC console
├── ai/             AI layer: RAG knowledge base, ATT&CK dataset, vector
│                   store, and the build/evaluation tooling
├── docs/           DOCUMENTATION.md, interview-prep.md, Postman collection
└── docker-compose.yml
```

The RAG *runtime code* lives in `backend/app/rag/` because the API service imports it directly; `ai/` holds the corpus, the vector store and the tooling that builds them. [`docs/DOCUMENTATION.md`](docs/DOCUMENTATION.md) explains that split.

## Quick start

```bash
cp .env.example .env      # add a free-tier Groq API key, admin username/password hash, session secret
docker compose up -d db   # PostgreSQL on host port 5433

cd backend
python -m venv venv && ./venv/Scripts/python.exe -m pip install -r requirements.txt
./venv/Scripts/python.exe -m alembic upgrade head
./venv/Scripts/python.exe -m uvicorn app.main:app --port 8000

cd ../frontend
npm install && npm run dev
```

Then open http://localhost:5173. The API serves docs at http://127.0.0.1:8000/docs.

To (re)build the knowledge base the AI layer retrieves from, run `python ai/tools/build_kb.py` from the repository root.

`docker compose up` brings up PostgreSQL, the backend, and a production frontend build served via nginx (`http://localhost:5173`); for day-to-day frontend development, run the Vite dev server instead (`cd frontend && npm run dev`).

## Tech stack
| Layer | Technology |
|---|---|
| Backend | FastAPI, SQLAlchemy, Alembic |
| Database | PostgreSQL |
| Detection | Sigma-style YAML rules (`pySigma`) |
| ATT&CK mapping | MITRE ATT&CK (official STIX/JSON dataset) |
| AI / RAG | LangChain, ChromaDB, Sentence Transformers, Groq |
| Frontend | React 19, Vite, Tailwind CSS v4, Recharts |
| Deployment | Docker Compose |

## Status

**Complete.** Backend, detection, AI/RAG, real admin authentication, and the frontend console are built and working end to end: a real admin login gates every protected route, EVTX upload creates real incidents, the explain and chat endpoints answer from the knowledge base with source attribution, and the console renders all of it from live API data. The backend test suite is 534 tests. Detection accuracy is tracked against a real-world EVTX corpus (`backend/scripts/run_detection_benchmark.py`), not just synthetic fixtures — currently 50/61 (82.0%) with 0 false positives; this number moves if the corpus or rule set changes, so treat it as a snapshot and re-run the script for the current figure. See `docs/DOCUMENTATION.md` and `backend/scripts/failure_matrix.md` (the generated, always-current source of truth) for the full breakdown.

Deliberately **not** implemented, because nothing in the system could honestly back them, or because they don't fit a single-admin deployment: threat-intel feeds, a geographic attack map, host CPU/memory/disk telemetry, and multi-user accounts/RBAC. Where a design reference called for one of those, the UI shows a real equivalent instead.

## Documentation

- [`docs/DOCUMENTATION.md`](docs/DOCUMENTATION.md) — the single reference document: pipeline, data model, API surface, detection engine, AI layer with its evaluation results, authentication, Demo Mode, frontend design system, the honesty policy, setup/running/testing/troubleshooting, and the full decision log + engineering history.

## Team
A 4-person team, working as two rotating pairs across backend, AI/RAG, and frontend tracks, swapping in the frontend phase so everyone touches at least two of the three layers.

## License
See [`LICENSE`](LICENSE).
