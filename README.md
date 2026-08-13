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
Day 4 of the 25-day roadmap (both pairs). Pair 1 (backend/detection): FastAPI skeleton, DB models/migrations, and EVTX reading + JSON conversion are done. Pair 2 (AI/RAG): ChromaDB + embeddings setup, MITRE ATT&CK loader, and the real knowledge-base build are done. See [`docs/02_NightOwl_Handbook_Vol2_Roadmap.md`](docs/02_NightOwl_Handbook_Vol2_Roadmap.md) for the day-by-day roadmap and [`docs/05_NightOwl_Manual_Testing_Guide.md`](docs/05_NightOwl_Manual_Testing_Guide.md) for verified manual test steps.

## License
See [`LICENSE`](LICENSE).
