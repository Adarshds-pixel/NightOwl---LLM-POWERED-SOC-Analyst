# NightOwl — Explainable Windows Threat Detection for the SOC

NightOwl turns Windows event-log exports (EVTX: Sysmon, Security, PowerShell, System, Application) into a small number of prioritized, explained incidents. Sigma-style rules and multi-event sequence detectors find the activity and map it to MITRE ATT&CK; a retrieval-grounded LLM explains each incident in plain English with its sources; a React SOC console shows all of it — so a junior analyst can go from "Event ID 1, `powershell -e JAB...`" to "this is encoded PowerShell execution (T1059.001) — here is why it was flagged and what to check next".

A final-year major project built by a team of 4, AI-assisted.

## Features
- EVTX upload (up to 100 MB) with per-file telemetry profiling: which channels and event types were in the file, and which of them any rule can evaluate
- **Detection:** 59 Sigma-style YAML rules + 8 multi-event sequence detectors (brute force, Kerberos password spray, group-membership abuse, SAM/LSA enumeration, mass process access, Process Herpaderping, SMB share enumeration). Rules are validated at load time — an unscoped rule, an unsupported modifier, an unparseable condition or an ATT&CK tag that does not belong to the rule's technique is rejected, not silently loaded
- ATT&CK v19.2 technique mapping (dataset bundled — no network needed) and tactic-weighted severity
- Incident grouping per host with a sliding one-hour window, status workflow, alert de-duplication, audit trail
- RAG explanations and incident chat (ChromaDB + sentence-transformers + Groq), with a self-critique pass, source attribution, prompt-injection containment for log content and flagging of any ATT&CK id the model invents
- An advisory "second opinion" on telemetry no rule covers
- **Experimental ML anomaly layer** — per-log-family models flag unusual 10-minute windows and record which features drove the score. It is supporting evidence only (advisory mode): it never opens or changes an incident and is never counted as a detection. See [`ML.md`](ML.md) for why
- SOC console: overview, incidents, investigation view and timeline, AI assistant, MITRE ATT&CK matrix, alerts (detections and ML anomalies kept apart), logs, rules, reports, settings with live system status, Demo Mode
- Single-admin authentication: bcrypt password, signed session cookie backed by a revocable server-side session, CSRF header check, failed-login throttling
- Free-tier only: Groq for the LLM, everything else open source and self-hosted

## Measured results

All numbers are produced by scripts in `backend/scripts/` and checked into the repo next to them — re-run a script to refresh them.

| What | Result | Source |
|---|---|---|
| Attack captures detected **with the correct ATT&CK technique** | **52 / 60** (86.7%) | `run_detection_benchmark.py` → `benchmark_results.md` |
| Attack captures raising any alert | 54 / 60 | same |
| False-positive alerts on 40 benign captures (316,874 events) | **5** — all real event-log clears on the benign machine | same |
| ML anomaly layer, held-out benign windows flagged | 1–4.5 per host-day (deployment protocol) | `eval_ml_model.py` → `ml_eval_results.json` |
| Backend tests | 740 offline + 5 integration | `pytest` / `pytest -m integration` |

Caveat on the detection numbers: every attack capture in the corpus informed rule development at some point, so these are development-set figures, not a held-out estimate. The 8 misses and why are listed in `backend/scripts/failure_matrix.md`.

## Repository structure

```
├── backend/        FastAPI service: API, detection engine + rules, ingestion,
│                   ATT&CK mapping, incident/severity services, RAG runtime,
│                   ML anomaly layer (app/ml/), models, Alembic migrations,
│                   tests, sample logs and the measurement scripts
├── frontend/       React + Vite + Tailwind SOC console (served by nginx in Docker)
├── ai/             RAG knowledge base (playbooks), vector store, KB build tooling
├── docs/           DOCUMENTATION.md, Postman collection
├── ML.md           The ML anomaly layer: design, evaluation, limits
└── docker-compose.yml
```

## Quick start (Docker — recommended)

```bash
cp .env.example .env
# Fill in: ADMIN_PASSWORD_HASH (bcrypt), SESSION_SECRET_KEY (32+ chars),
#          POSTGRES_PASSWORD, GROQ_API_KEY (free key from console.groq.com)
python -c "import bcrypt; print(bcrypt.hashpw(b'choose-a-password', bcrypt.gensalt()).decode())"
python -c "import secrets; print(secrets.token_hex(32))"

docker compose up --build
```

Open http://localhost:5173 and sign in. On first start the backend applies database migrations and builds the knowledge base (this needs network access once, to download the embedding model). The backend refuses to start outside `APP_ENV=local` with a missing or short session secret or password hash.

## Local development

```bash
cp .env.example .env                     # APP_ENV=local
docker compose up -d db                  # PostgreSQL on 127.0.0.1:5433

cd backend
python -m venv venv && ./venv/Scripts/python -m pip install -r requirements-dev.txt
./venv/Scripts/python -m alembic upgrade head
./venv/Scripts/python ../ai/tools/build_kb.py          # once
./venv/Scripts/python -m uvicorn app.main:app --port 8000

cd ../frontend && npm ci && npm run dev                # http://localhost:5173
```

Tests: `cd backend && ./venv/Scripts/python -m pytest` (offline) and `-m integration` (needs the knowledge base and model downloads). Frontend: `npx tsc -b && npm run lint && npm run build`.

## Tech stack
| Layer | Technology |
|---|---|
| Backend | FastAPI, SQLAlchemy 2, Alembic, PostgreSQL 16 |
| Detection | Sigma-style YAML rules (validated with pySigma, evaluated by NightOwl's engine) + Python sequence detectors |
| ATT&CK | MITRE ATT&CK Enterprise v19.2 (bundled index) |
| AI / RAG | LangChain, ChromaDB, sentence-transformers, Groq |
| Anomaly detection | scikit-learn (Ledoit-Wolf covariance, Mahalanobis distance) |
| Frontend | React 19, Vite, Tailwind CSS v4, Recharts |
| Deployment | Docker Compose (Postgres, backend, nginx frontend) |

## Known limits
- Batch EVTX upload only — there is no live agent or streaming collector.
- The ML layer is trained on two benign machines; it stays advisory until a broader baseline is collected (`backend/scripts/collect_benign_logs.ps1`, then `train_ml_model.py --extra-dir ...`).
- Rules are tuned on a 60-capture public corpus; expect tuning (allow-lists) on a new environment.
- Single admin account; no RBAC or multi-tenancy.

## Documentation
- [`docs/DOCUMENTATION.md`](docs/DOCUMENTATION.md) — architecture, data model, API, detection engine, AI layer, security model, deployment, testing.
- [`ML.md`](ML.md) — the ML anomaly layer.
- `backend/scripts/benchmark_results.md`, `failure_matrix.md`, `ml_eval_results.json` — generated measurements.

## License
See [`LICENSE`](LICENSE).
