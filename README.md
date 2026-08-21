# NightOwl — AI-Powered Security Operations Center

NightOwl turns raw Windows Sysmon/EVTX telemetry into a small number of prioritized, explained incidents. It applies Sigma-style detection rules mapped to MITRE ATT&CK techniques, enriches each match with a Retrieval-Augmented Generation (RAG) LLM layer, and surfaces everything in a React dashboard — so a junior analyst can go from "Event ID 1, `powershell -enc ...`" to "this is obfuscated PowerShell execution (T1059.001) — isolate the host, capture memory, check the parent process chain" without needing years of SOC experience.

This is a final-year major project built by a team of 4, AI-assisted, over a 30-day roadmap. See [`docs/`](docs/) for the full engineering handbook.

## Features
- Batch ingestion of Sysmon EVTX log files
- Rule-based detection engine (Sigma-style YAML rules)
- Automatic MITRE ATT&CK technique mapping + severity scoring
- RAG pipeline (ChromaDB + LangChain + LLM) generating grounded, plain-English incident explanations and recommended responses
- **Self-critique reasoning chain** — the LLM checks its own draft explanation against the retrieved sources before returning it, instead of a single-shot prompt
- **Source-attribution UI** — every explanation shows the exact knowledge-base chunks + similarity scores it was grounded in
- Dashboard: incident feed, incident detail, MITRE ATT&CK heatmap, and an "ask the incident" chat interface
- Runs entirely on **free-tier tools** (Gemini free tier / Groq for the LLM; everything else is open-source/self-hosted) — **$0 to build and run**

## Architecture
See [`docs/01_NightOwl_Handbook_Vol1_Overview_Architecture.md`](docs/01_NightOwl_Handbook_Vol1_Overview_Architecture.md) for the full architecture, data flow, and folder structure.

## Quick Start
```bash
git clone <repo>
cp .env.example .env   # fill in your free-tier LLM API key (Gemini free tier or Groq)
docker compose up
```
Then open http://localhost:5173

> Backend, frontend, and Docker setup are not built yet — this project is still pre-development. See [`docs/02_NightOwl_Handbook_Vol2_Roadmap.md`](docs/02_NightOwl_Handbook_Vol2_Roadmap.md) for the current day-by-day roadmap.

## Tech Stack
| Layer | Technology |
|---|---|
| Backend | FastAPI, SQLAlchemy, Alembic |
| Database | PostgreSQL |
| Detection | Sigma-style YAML rules (`pySigma`) |
| Threat Intel | MITRE ATT&CK (official STIX/JSON dataset) |
| AI / RAG | LangChain, ChromaDB, Sentence Transformers, an LLM provider API |
| Frontend | React, Vite, Tailwind CSS |
| Deployment | Docker Compose |

## Team
A 4-person team, working as two rotating pairs across backend, AI/RAG, and frontend tracks. See [`docs/02_NightOwl_Handbook_Vol2_Roadmap.md`](docs/02_NightOwl_Handbook_Vol2_Roadmap.md) for the current pair assignments and roadmap.

## Project Status
Pair 1 (backend/detection) has reached Day 13 of the 26-day roadmap — **Milestone: Backend + Detection core complete** (Day 12), plus Day 13's production-hardening pass. On top of Day 11's work (FastAPI skeleton, DB models/migrations, EVTX reading + JSON conversion, the normalized event schema + persistence, the `POST /ingest` endpoint, detection engine v1, the Day 7 clean-VM Sysmon Event ID 3 capture, 10 detection rules + alert persistence, incident grouping v1, severity scoring v1, and MITRE technique validation), Day 12 adds: `GET /incidents` (filtered by severity/status/date range) and `GET /incidents/{id}` (alerts + their events + resolved MITRE technique info); 5 more Sigma rules covering credential access (LSASS memory dump, SAM/SYSTEM/SECURITY hive dump) and lateral movement (RDP, WinRM, admin-share) — 15 rules total; a consistent JSON error shape for unhandled exceptions across every route (`core/errors.py`); structured JSON logging (`core/logging.py`, stdlib-only); and an end-to-end integration test proving the real pipeline — real rule set, real detection, real incident grouping, real MITRE lookup — turns a sample log into incidents with resolved techniques (`tests/test_ingest_flow.py`). Day 13 adds `X-API-Key` header auth on every route (`core/auth.py`, disabled by default), `limit`/`offset` pagination on `GET /incidents` with a page-independent `total`, an in-memory token-bucket rate limiter (`core/rate_limit.py`), and a multi-stage non-root `backend/Dockerfile` + `backend` service in `docker-compose.yml`. See `docs/decisions.md` for the rule/logging design notes. Pair 2 (AI/RAG) has reached Day 11: on top of Day 9's work (ChromaDB + embeddings setup, MITRE ATT&CK loader, the real knowledge-base build, top-k retrieval with a manual retrieval-quality check, see `docs/research/retrieval-eval.md`, the `GET /mitre/techniques` endpoint + validator scaffold, the explanation prompt template + Gemini LLM client wiring, `explain_service`'s retrieve → draft → self-critique pipeline, and the `POST /incidents/{id}/explain` endpoint), Day 10 adds a hallucination spot-check (`docs/research/hallucination-eval.md`) plus Groq wired in as an alternate LLM provider, and Day 11 adds the incident chat data model and the `POST /incidents/{id}/chat` endpoint (retrieval-grounded follow-up Q&A with source attribution). See `docs/decisions.md` for the LLM-provider and chat design notes. See [`docs/02_NightOwl_Handbook_Vol2_Roadmap.md`](docs/02_NightOwl_Handbook_Vol2_Roadmap.md) for the day-by-day roadmap and [`docs/05_NightOwl_Manual_Testing_Guide.md`](docs/05_NightOwl_Manual_Testing_Guide.md) for verified manual test steps.

## License
See [`LICENSE`](LICENSE).
