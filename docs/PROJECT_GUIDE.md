# NightOwl — Project Guide

Setup, running, testing, troubleshooting, roadmap and working conventions.
Companion document: [`ARCHITECTURE.md`](ARCHITECTURE.md) for how the system is designed.

---

## 1. Prerequisites

- **Python 3.10+** with a virtualenv at `backend/venv`.
- **Node 20+** for the frontend.
- **Docker Desktop** running, for PostgreSQL (`docker info` must succeed). Only the database needs it; the test suite and the AI tooling run without Docker.
- Repo-root `.env`, copied from `.env.example` and filled in with a free-tier LLM key.

### Windows setup issues that cost real time

| Symptom | Fix |
|---|---|
| `SSLError: CERTIFICATE_VERIFY_FAILED` reaching GitHub or HuggingFace | Corporate/AV TLS interception that Windows trusts but Python's bundled certifi does not. `pip install pip-system-certs` once per venv. |
| `pip install -r requirements.txt` fails building `hexdump` with an `AssertionError` in `_distutils_hack` | A python-evtx sub-dependency hitting a setuptools/distutils conflict. Install with `SETUPTOOLS_USE_DISTUTILS=stdlib` set. |
| `ModuleNotFoundError: langchain_groq` in an otherwise working venv | requirements.txt gained a dependency after the venv was created. Re-run the install after every pull, not only on first setup. |

---

## 2. Running the stack

```bash
# 1. Database
docker compose up -d db                 # PostgreSQL 16 on host port 5433

# 2. Backend
cd backend
python -m venv venv
SETUPTOOLS_USE_DISTUTILS=stdlib ./venv/Scripts/python.exe -m pip install -r requirements.txt
./venv/Scripts/python.exe -m alembic upgrade head
./venv/Scripts/python.exe -m uvicorn app.main:app --port 8000

# 3. Frontend
cd frontend
npm install
npm run dev                             # http://localhost:5173
```

API docs are at http://127.0.0.1:8000/docs.

**Rebuilding the knowledge base** (only needed after editing playbooks, or on a fresh clone):

```bash
python ai/tools/build_kb.py             # run from the repository root
```

First run downloads the sentence-transformers weights and the ATT&CK bundle, and takes a minute or two. Subsequent runs use the local caches.

---

## 3. Environment variables

Everything lives in the repo-root `.env`; see `.env.example` for the annotated template.

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | postgres on 5433 | SQLAlchemy connection string |
| `LLM_PROVIDER` | `gemini` (example file sets `groq`) | Which provider `rag/llm_client.py` builds |
| `LLM_API_KEY` / `GROQ_API_KEY` | empty | Provider credential; missing key gives a 503, not a crash |
| `LLM_MODEL` / `GROQ_MODEL` | `gemini-flash-latest` / `openai/gpt-oss-120b` | Model override |
| `LLM_TIMEOUT_SECONDS` | 30 | Per-call provider timeout |
| `RESPONSE_CACHE_ENABLED` | true | Route-level explain/chat cache |
| `API_KEY` | empty (auth disabled) | Shared secret checked as the `X-API-Key` header |
| `RATE_LIMIT_PER_MINUTE` | 300 | Per-IP token bucket; 0 or less disables it. `/health` is exempt |
| `CORS_ALLOW_ORIGINS` | localhost:5173 | Add any other origin the console is served from |

Frontend variables live in `frontend/.env.local` (`VITE_API_BASE_URL`, `VITE_API_KEY`) and are baked into the bundle at build time.

---

## 4. Testing

```bash
cd backend && ./venv/Scripts/python.exe -m pytest -q     # 344 tests
cd frontend && npm run build && npm run lint             # typecheck + build + oxlint
```

The backend suite runs fully offline against in-memory SQLite: the shared `api_client` fixture in `tests/conftest.py` wires the real FastAPI app to a fresh database per test with a `get_db` override, so route tests exercise real HTTP behaviour without Postgres. Tests mirror the app package layout (`tests/api`, `tests/detection`, `tests/services`, `tests/ingestion`, `tests/mitre`, `tests/rag`, `tests/core`).

A few checks need network or a live database and are excluded from the offline path: the RAG integration tests (model weights, ATT&CK download) and anything touching Postgres or a real LLM call.

### Manual end-to-end verification

1. Start the database, backend and frontend as above.
2. Open http://localhost:5173 and upload `backend/sample_logs/sysmon_malicious_demo.evtx` from the Overview or Logs page. This fixture trips several of the loaded rules across multiple techniques.
3. Confirm incidents appear with severities and technique ids, and that Alerts, Logs, MITRE and Rules all populate.
4. Open an incident, run the AI analysis, and confirm the explanation returns with source chunks and a self-critique result.
5. Ask a follow-up in the chat panel; confirm it answers and the audit trail records the calls.
6. `/demo` runs that whole sequence end to end with terminal narration, against the same real endpoints.

### Verifying a specific behaviour quickly

```bash
curl http://127.0.0.1:8000/health
curl "http://127.0.0.1:8000/incidents?limit=2"
curl "http://127.0.0.1:8000/events?alert_only=true&limit=3"
curl http://127.0.0.1:8000/rules | head -c 400
curl -X POST http://127.0.0.1:8000/incidents/1/explain      # costs 2 LLM requests
```

A Postman collection covering every endpoint is in `docs/postman/`.

---

## 5. Demonstrating the project live

`/demo` (**Demo Mode**) is the fastest way to show the whole pipeline to a panel without manually driving every page. Each run rotates through a bundled pool of real attack fixtures and drives the exact same calls a real user would trigger by hand -- `POST /ingest`, then `/explain`, then a scripted chat question -- narrated in a terminal-style log as each request completes. See [`ARCHITECTURE.md` §10](ARCHITECTURE.md#10-demo-mode) for why nothing in it is fabricated or pre-recorded.

**During the demo, on `/demo`:**

1. Optionally click **Reset demo data** first (confirm the dialog) so the console starts empty -- "this is a SOC with no telemetry yet."
2. Click **Run demo**. Narration advances through Ingest -> Resolve incident -> Explain -> Chat, each line appearing only once its real backend call returns.
3. Open the resolved incident badge the card links to, and walk through its Evidence, MITRE techniques, and AI Analysis tabs exactly as in the one-shot walkthrough above.
4. Point out the chat answer came back live, not canned, and show the audit trail.
5. Run it again to rotate to the next fixture in the pool if time allows -- each run is independent and safe to repeat.

**If something goes wrong live:** click **Reset demo data** and run again -- ingestion is idempotent per fixture and safe to retry. Any failure surfaces inline in the terminal log with the real error text; the backend terminal also logs the full traceback.

**No admin rights / no Sysmon on the demo machine needed:** Demo Mode reads pre-built `.evtx` fixtures already committed under `frontend/public/demo/`, so it works on any machine that can run the frontend and reach the backend.

---

## 6. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `failed to connect to the docker API` | Docker Desktop is not running (it does not auto-start on the dev machine) | Launch it, wait ~20s, retry |
| `pg_isready` never succeeds, or port 5433 in use | Another Postgres owns the port, or the container needs more time | `docker compose ps`, `docker compose logs db` |
| First run of the RAG tests or `build_kb.py` takes 1-2 minutes | sentence-transformers and the ATT&CK bundle downloading | Expected once; later runs use local caches |
| Port 8000 still bound after stopping uvicorn | A reloader child process survived | `netstat -ano \| findstr :8000` then `taskkill /F /PID <pid>` |
| `POST /ingest` returns 500 with `psycopg2.OperationalError ... port 5433` | No live Postgres | Start the database (section 2) |
| `POST /incidents/{id}/explain` returns 503 with `429 RESOURCE_EXHAUSTED` | Free-tier daily quota exhausted; each explain costs two provider requests | Wait for the reset, or switch `LLM_PROVIDER` to the other provider |
| `LLMProviderError ... 503 UNAVAILABLE ... high demand` | Transient provider overload | Retry; the client already retries once automatically |
| Explain returns 500 while the same call works in a script | Legacy console encoding could not write a log line containing typographic punctuation | Fixed: the JSON formatter escapes non-ASCII and the handler forces UTF-8 |
| The console shows "rate limit exceeded" and will not recover for minutes | Token bucket drained; background pollers consumed the refill before a page could accumulate what it needed | Fixed: `/health` exempt, ceiling raised to 300/min, searches debounced, GETs de-duplicated, pollers pause when hidden and back off on 429 |
| Any test using `tmp_path` fails with `PermissionError: [WinError 5]` | Broken Windows temp-directory ACL on the dev machine | Handled automatically by `tests/conftest.py`, which redirects `--basetemp` |
| Tests hit the real LLM instead of mocks | `.env` left on `groq`, while the test file only mocks the Gemini branch | Set `LLM_PROVIDER=gemini` when you are done testing against Groq |
| `docker compose build backend` fails with certificate errors from PyPI | Same TLS interception as section 1, but inside the container | Already handled in `backend/Dockerfile` via trusted-host flags |
| `ChatGroq(timeout=...)` appears to do nothing | The field is `request_timeout` for Groq and `timeout` for Gemini | Use the right name per provider; the wrong one is silently ignored |

### Field note: capturing real Sysmon telemetry

Network-connection events (Sysmon Event ID 3) could not be captured on the primary dev laptop: McAfee's WFP-based firewall blocks Sysmon's network-monitoring driver, confirmed through read-only diagnostics. The workaround was to capture on a clean VM with a minimal ProcessCreate + NetworkConnect + FileCreate configuration. The resulting fixtures live in `backend/sample_logs/`.

---

## 7. Roadmap and status

A 30-day plan compressed to 26, run by a 4-person team as two rotating pairs (backend/detection and AI/RAG), swapping tracks in the frontend phase so everyone touches at least two of the three layers.

| Phase | Days | Outcome |
|---|---|---|
| Research, planning, design | 1-2 | Stack chosen, free-tier-only LLM policy, wireframes |
| Backend core and detection | 3-12 | FastAPI, DB models and migrations, EVTX ingestion, normalization, detection engine, 29 rules, alert persistence, incident grouping, severity scoring, MITRE validation, incident endpoints |
| AI / RAG | 3-12 | ChromaDB and embeddings, ATT&CK loader, knowledge-base build, retrieval, prompts and LLM client, explain with self-critique and source attribution, incident chat |
| Production hardening | 13 | API key auth, pagination, rate limiting, response caching, audit log, CI pipeline, backend Dockerfile |
| Frontend | 14-20 | Vite/React scaffold, then the full SOC console redesign |
| Integration and testing | 21-22 | Coverage push, edge cases, end-to-end runs |
| Deployment | 23-24 | Containers and compose, clean-machine tests |
| Demo and report | 25-26 | Final report, presentation |

**Where things actually stand.** Backend, detection, AI/RAG and the console are built and working end to end; the backend suite is 382 tests. The console covers Overview, Incidents, Incident detail, AI Assistant, MITRE ATT&CK, Alerts, Logs, Rules Engine, Reports, Settings and Demo Mode, all bound to live API data.

Still open: a responsive and accessibility sweep at laptop and tablet widths, a frontend Dockerfile and full-stack compose, and the formal testing report.

**Deliberately not built** (see the honesty policy in ARCHITECTURE.md section 9): threat-intel feeds, a geographic attack map, host CPU/memory/disk telemetry, and user accounts.

---

## 8. Working conventions

- **Commits** follow Conventional Commits (`feat:`, `fix:`, `chore:`, `docs:`, `test:`, `style:`), one line, describing the behaviour change rather than the file touched.
- **Layering** is enforced by review: routes compose services, services own database access, models stay dumb. A route that queries the database directly is a bug.
- **Comments explain why, not what.** Every non-obvious decision in the codebase carries the reasoning and the alternative that was rejected; the decision log in ARCHITECTURE.md is the long form of the same habit.
- **Tests mirror the package they cover** and are named for the module, not for the day the work happened.
- **Nothing that cannot be backed by real data ships to the UI.** If a panel cannot be populated honestly, it is replaced by one that can, and the substitution is recorded.
- **Free-tier only.** No paid API is used anywhere in this project, which is why LLM quota management (caching, two-call awareness, provider fallback) is a design concern rather than an afterthought.
