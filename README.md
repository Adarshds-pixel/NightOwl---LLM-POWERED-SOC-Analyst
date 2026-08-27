# NightOwl — AI-Powered Security Operations Center

NightOwl turns raw Windows Sysmon/EVTX telemetry into a small number of prioritized, explained incidents. It applies Sigma-style detection rules mapped to MITRE ATT&CK techniques, enriches each match with a Retrieval-Augmented Generation (RAG) LLM layer, and surfaces everything in a React SOC console — so a junior analyst can go from "Event ID 1, `powershell -enc ...`" to "this is obfuscated PowerShell execution (T1059.001) — isolate the host, capture memory, check the parent process chain" without needing years of SOC experience.

This is a final-year major project built by a team of 4, AI-assisted, over a 30-day roadmap.

## Features
- Batch ingestion of Sysmon EVTX log files
- Rule-based detection engine (15 Sigma-style YAML rules, `pySigma`-validated)
- Automatic MITRE ATT&CK technique mapping + severity scoring
- Incident grouping, status workflow, and a backend audit trail
- RAG pipeline (ChromaDB + LangChain + LLM) generating grounded, plain-English incident explanations and recommended responses
- **Self-critique reasoning chain** — the LLM checks its own draft explanation against the retrieved sources before returning it, instead of a single-shot prompt
- **Source-attribution UI** — every explanation shows the exact knowledge-base chunks + similarity scores it was grounded in
- SOC console: overview dashboard, incident queue and investigation view, AI assistant, MITRE ATT&CK coverage, alerts, log explorer, rules engine, reports and settings
- Runs entirely on **free-tier tools** (Gemini free tier / Groq for the LLM; everything else is open-source/self-hosted) — **$0 to build and run**

## Repository structure

Three layers, one directory each.

```
├── backend/        FastAPI service: API routes, detection engine, ingestion,
│                   MITRE mapping, incident/severity services, DB models,
│                   Alembic migrations, tests, and EVTX sample_logs
├── frontend/       React + Vite + Tailwind SOC console
├── ai/             AI layer: RAG knowledge base, ATT&CK dataset, vector
│                   store, and the build/evaluation tooling
├── docs/           ARCHITECTURE.md, PROJECT_GUIDE.md, Postman collection
└── docker-compose.yml
```

The RAG *runtime code* lives in `backend/app/rag/` because the API service imports it directly; `ai/` holds the corpus, the vector store and the tooling that builds them. [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) explains that split.

## Quick start

```bash
cp .env.example .env      # add a free-tier LLM API key (Gemini or Groq)
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

`docker compose up` currently brings up PostgreSQL and the backend; the frontend runs from the Vite dev server.

## Tech stack
| Layer | Technology |
|---|---|
| Backend | FastAPI, SQLAlchemy, Alembic |
| Database | PostgreSQL |
| Detection | Sigma-style YAML rules (`pySigma`) |
| ATT&CK mapping | MITRE ATT&CK (official STIX/JSON dataset) |
| AI / RAG | LangChain, ChromaDB, Sentence Transformers, Gemini or Groq |
| Frontend | React 19, Vite, Tailwind CSS v4, Recharts |
| Deployment | Docker Compose |

## Status

Backend, detection, AI/RAG and the frontend console are built and working end to end: EVTX upload creates real incidents, the explain and chat endpoints answer from the knowledge base with source attribution, and the console renders all of it from live API data. The backend test suite is 288 tests.

Deliberately **not** implemented, because nothing in the system could honestly back them: threat-intel feeds, a geographic attack map, host CPU/memory/disk telemetry, and user accounts. Where a design reference called for one of those, the UI shows a real equivalent instead — documented in the frontend phase notes.

## Documentation

Two documents, kept current:

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — how the system works: pipeline, data model, API surface, detection engine, AI layer with its evaluation results, frontend design system, the honesty policy, and the full decision log.
- [`docs/PROJECT_GUIDE.md`](docs/PROJECT_GUIDE.md) — setup, running, environment variables, testing and manual verification, troubleshooting, roadmap and status, working conventions.

## Team
A 4-person team, working as two rotating pairs across backend, AI/RAG, and frontend tracks, swapping in the frontend phase so everyone touches at least two of the three layers.

## License
See [`LICENSE`](LICENSE).
