# NightOwl — Documentation

Everything about how NightOwl is built, why, how to run and test it, and how it got here. This is the single reference document for the project — it replaces what used to be five separate files (`ARCHITECTURE.md`, `PROJECT_GUIDE.md`, `FRONTEND_KPI_AUDIT.md`, `final_plan.md`, `pending.md`), merged and curated into one place now that the project is complete.

---

## 1. What NightOwl does

NightOwl turns raw Windows Sysmon/EVTX telemetry into a small number of prioritised, explained incidents. It is not "a SOC platform that detects every attack" — no static EVTX analyzer can honestly promise that. It is an evidence-driven investigation platform that profiles Windows telemetry, detects known malicious behaviours, maps findings to MITRE ATT&CK, and uses grounded AI to explain what happened — while being explicit about what the available telemetry cannot determine.

```
EVTX upload
   |
   v
Ingestion     evtx_reader -> normalizer -> NormalizedEvent   --> events table
   |
   v
Detection     45 Sigma-style YAML rules + a 3-pattern sequence
              engine, evaluated per event / per batch          --> alerts table
   |          severity = Sigma level + MITRE tactic weight
   v
Correlation   alerts grouped per host within a 1h window     --> incidents table
   |          incident carries the union of technique ids
   v
AI layer      retrieve (ChromaDB) -> draft (LLM) -> self-critique (LLM)
   |          returns explanation + confidence breakdown (Fact/
   |          Inference/Uncertainty) + recommended response + sources
   v
Console       React SOC UI over the REST API, behind a real admin login
```

Every number the console shows is derived from this pipeline. Nothing is simulated.

---

## 2. Repository layout

```
├── backend/        FastAPI service: API routes, detection engine, ingestion,
│                   MITRE mapping, incident/severity services, DB models,
│                   Alembic migrations, tests, and EVTX sample_logs
├── frontend/       React + Vite + Tailwind SOC console
├── ai/             AI layer: RAG knowledge base, ATT&CK dataset, vector
│                   store, and the build/evaluation tooling
├── docs/           This file, Postman collection, audits/
└── docker-compose.yml
```

The RAG *runtime code* lives in `backend/app/rag/` because the API service imports it directly (`app.rag.explain_service`); `ai/` holds the corpus, the vector store and the tooling that builds them. Splitting it into a separately installed package would buy indirection rather than clarity at this size.

**Backend layering rule:** routes → services → models/db. Only the service layer talks to the database; routes compose services and own their Pydantic response models (file-local, no shared `schemas/` layer).

---

## 3. Data model

PostgreSQL 16 (host port 5433), SQLAlchemy 2 declarative models, Alembic migrations.

| Table | Key fields |
|---|---|
| `events` | `id`, `host`, `timestamp`, `event_id`, `process`, `parent_process`, `command_line`, `user`, `raw_json` |
| `alerts` | `id`, `event_id` → events, `rule_id` (Sigma UUID), `matched_at`, `severity`, `incident_id` |
| `incidents` | `id`, `title`, `status`, `severity`, `host`, `mitre_technique_ids` (JSON list), `created_at` |
| `chat_messages` | `id`, `incident_id`, `role`, `content`, `created_at` |
| `audit_log` | `id`, `entity_type`, `entity_id`, `action`, `actor`, `details`, `created_at` |
| `rules` | Defined but unused — detection rules live as YAML files, not rows |

`raw_json` stores both the original record and the normalized view, so fields the normalizer does not promote to columns (Hashes, the network 5-tuple) are never lost.

**Severity vocabulary**, shared verbatim by the backend, the API and the UI: `informational | low | medium | high | critical`.

**Session state** (admin login only, see §10) lives entirely in a signed cookie — there is no `sessions` or `users` table. A single admin account is configured via environment variables, not a database row.

---

## 4. API surface

All routes are mounted at root. `/health` is always public. Every other route sits behind `require_api_key` (an optional shared secret, off by default) **and** `require_session_auth` (the real admin login, always enforced — see §10).

| Method | Path | Notes |
|---|---|---|
| GET | `/health` | Liveness only. Public, exempt from rate limiting. |
| POST | `/auth/login` | Admin login — sets the session cookie |
| POST | `/auth/logout` | Clears the session |
| GET | `/auth/me` | Current session's username, or 401 |
| POST | `/ingest` | multipart `.evtx` upload; returns counts + created incident ids |
| GET | `/mitre/techniques` | Full ATT&CK Enterprise catalog |
| GET | `/incidents` | Filters: `severity`, `status`, `start_date`, `end_date`, `q`, `limit` (max 200), `offset` |
| GET | `/incidents/{id}` | Incident + alerts + their events + resolved techniques |
| PATCH | `/incidents/{id}/status` | open, investigating, resolved, closed; writes an audit row |
| GET | `/incidents/{id}/audit` | Audit trail for one incident |
| POST | `/incidents/{id}/explain` | RAG explanation + recommended response + source chunks |
| POST/GET | `/incidents/{id}/chat` | Incident-scoped chat turn / history |
| GET | `/events` | Raw timeline. Filters: `host`, `start_date`, `end_date`, `alert_only`, `q`, `limit`, `offset` |
| GET | `/events/{id}` | One event including `raw_json` |
| GET | `/rules`, `/rules/{rule_id}` | Loaded rule set + per-rule match counts and last-triggered |
| POST | `/demo/reset` | Deletes every event/alert/incident/chat/audit row |
| GET | `/demo/fixtures` | Lists the real-world fixtures the current rule set detects |
| GET | `/demo/fixtures/{filename}` | Streams one fixture's raw bytes |

The three `/demo/*` routes sit behind an additional `require_demo_mode` gate (`DEMO_MODE_ENABLED`, on by default) on top of the usual auth, since `/demo/reset` is destructive and the other two expose internal fixture paths.

Error shape is uniform: `{"detail": "<string>"}`. `LLMProviderError` gives 503; anything unhandled gives 500; throttled gives 429.

**No sorting parameters and no aggregate/stats endpoints** — list endpoints are hardcoded newest-first, and every dashboard figure is computed client-side from the pages the console already fetched.

**No websocket or SSE.** Live data in the console is polling, deliberately: building a streaming transport purely so the UI could feel live would be backend scope with no other consumer.

---

## 5. Detection engine

Rules are Sigma-style YAML files in `backend/app/detection/rules/` (**45** as of this writing), loaded once at first use and cached in-process.

- **pySigma is used for validation only.** Its design centres on backends that convert a rule into a target query language (Elasticsearch DSL, Splunk SPL) to run against an external log store; there is no official backend for evaluating a rule against a single in-memory dict, which is exactly what `POST /ingest` needs. So `SigmaRule.from_yaml()` validates structure (real errors, not decoration) and a small hand-rolled interpreter in `engine.py` evaluates the `detection` block parsed separately with `yaml.safe_load`.
- **Supported subset:** named selections (AND across fields, OR across a value list), contains/startswith/endswith/exact modifiers, all case-insensitive, and a boolean condition string (and/or/not/parentheses) via a recursive-descent parser, not `eval()`, since rule files are treated as untrusted input.
- **Not supported (by design, v1):** regex and glob modifiers, "1 of"/"all of" shorthand, named multi-condition rules.
- **Rules match real Sysmon field names** (Image, CommandLine, DestinationIp) rather than an invented vocabulary, so they stay portable from public SigmaHQ sources. `NormalizedEvent.event_data` carries the full flattened EventData dict, so the engine sees every field without re-parsing XML.
- **Channels covered:** Sysmon, Windows Security, and PowerShell/Operational (4104/4103 script-block logging).

**Severity scoring** (`services/severity_service.py`): base Sigma level rank (1–5) plus the highest MITRE tactic weight among the rule's own tags: 0 for reconnaissance and resource-development, +1 for initial-access, execution, persistence, privilege-escalation and defense-evasion, +2 for credential-access, discovery, lateral-movement and collection, +3 for command-and-control, exfiltration and impact; capped at critical.

**Incident grouping** (`services/incident_service.py`): a match joins the most recent open incident for the same host within a 1-hour window, merging its technique id and raising severity to the higher of the two; otherwise a new incident is created.

**Coverage:** execution (encoded PowerShell, execution-policy bypass, LOLBin execution, mshta, certutil download, suspicious writes to public/temp), persistence (Run keys, IFEO debugger, scheduled tasks — both Sysmon-process-creation and native Security 4698, WMI event consumers, accessibility-tool hijack), privilege escalation & defense evasion (UAC bypass/disable, rogue named pipes, timestomping, LOLDriver loads, audit log cleared, audit policy weakened, unmanaged PowerShell engine loads), credential access (LSASS dumps via 2 different signals, SAM/SYSTEM/SECURITY hive dumps, DCSync, remote registry access), discovery (sensitive group/account enumeration, SAM privileged-group object access), lateral movement (RDP, admin share, WinRM, loopback-tunnelled RDP), command and control (LOLBin network connections), and 3 PowerShell-specific rules (LSASS dump via reflection, fake credential prompts, WebClient download cradles).

**Two mechanisms sit outside the single-event Sigma engine entirely, both narrow and built only once real fixture data justified them:**

- **The sequence engine** (`detection/sequences.py`) hand-codes 3 multi-event correlations no single-event rule can express: Process Herpaderping (FileCreate → ProcessAccess → ImageLoad, chained via Sysmon `ProcessGuid`, T1055), an SMB share-enumeration probe (a `\srvsvc` PipeConnect corroborated by an inbound port-445 connection, T1135), and a Kerberos password spray (≥4 distinct `TargetUserName` values from one source IP within 60s, T1110.003). It runs once per ingest batch after the per-event rule loop, feeding the same alert/incident creation path a normal rule match uses.
- **Advisory patterns** (`services/advisory_patterns.py`) are narrow event shapes too false-positive-prone for a deterministic rule (e.g. `\lsass`/`\srvsvc` named-pipe connects from `System`) but still worth a human second look — routed to the LLM advisory second-opinion mechanism instead, never creating an Alert/Incident of their own.

**Verifying detection accuracy** — see §14.

---

## 6. MITRE ATT&CK mapping

- Official STIX bundle (ATT&CK v19.2), downloaded on first use and cached at `ai/mitre/enterprise-attack.json`.
- Per technique: id, name, description, tactics, is_deprecated, is_revoked.
- **Two tactic vocabularies exist and must be normalised when joined.** The ATT&CK dataset returns hyphenated kill-chain phase names (`defense-evasion`), while this project's rule tags use underscores (`defense_evasion`).
- **This dataset does not use "defense-evasion" as a tactic string at all** — it's split into `stealth` (general case) and `defense-impairment` (tool/log tampering specifically). The frontend's `TACTIC_ORDER` includes both, mapped to "Defense Evasion" and "Defense Impairment" respectively — a real gap found and fixed during frontend QA (see §16).
- **Invalid technique tags are warn-only, never rule-rejecting.** A bad tag is a metadata problem; the rule's detection logic still works and should keep firing.

---

## 7. AI / RAG layer

### Corpus and retrieval

`ai/tools/build_kb.py` chunks MITRE technique descriptions (skipping deprecated/revoked ones) plus hand-written playbooks in `ai/knowledge_base/playbooks/`, embeds them with sentence-transformers `all-MiniLM-L6-v2`, and writes a single collection into `ai/vector_store/` (~1,900 chunks, 800 chars with 100-char overlap). Retrieval is top-k (k=5) with an optional technique-id filter.

### Generation

`rag/explain_service.py` runs **retrieve, draft, self-critique**: one LLM call produces the explanation from the incident context plus retrieved chunks, and a second call checks that draft against both the chunks and the incident context. Flagged claims are appended as a confidence-check block. Every explanation also carries a mechanical **FACT / INFERENCE / UNCERTAINTY** breakdown, extracted from a required 4th section in the prompt (`extract_confidence_breakdown()`).

Chat (`rag/chat_service.py`) is a single call per turn, no critique pass — a real back-and-forth where the user can immediately challenge a wrong answer, and a second call would double the free-tier cost of every turn.

### What the model can see

`services/incident_service.py::build_incident_evidence()` pulls the incident's first alert's real process, parent process, command line, user, matched rule title, detection method (Sigma rule vs. sequence correlation), and up to 5 nearby related events into both the explain and chat prompts — not just `{title, severity, host, technique_id}`. Bounded to one alert's detail so a rule that fired dozens of times doesn't balloon the prompt.

### Provider, timeouts, caching

- **Groq, exclusively.** The call is abstracted behind `rag/llm_client.py`; there is no automatic fallback to any other provider — a Groq outage surfaces as a clean 503, not a silent swap. (Gemini was supported earlier and removed once its free tier proved structurally unreliable — hard 20-req/day quota plus server-side overload, both observed live.)
- Two caches: a route-level cache (`rag/cache.py`, on by default, keyed on incident id, TTL 900s) and a prompt-hash cache in `llm_client` (off by default, for manual testing without spending quota).
- Chat history sent to the LLM is bounded to the most recent 10 messages; the full conversation is still stored and returned via the API.
- One retry with a 2s delay; `LLMProviderError` surfaces as 503 with the provider's own message.

### Evaluation results (measured, not assumed)

**Retrieval quality** (10 queries): 9/10 returned the correct playbook/technique document in the top 3. The one failure was a corpus vocabulary gap (a query about "beaconing" under-retrieved the C2 playbook, which never uses that word).

**Hallucination spot-check** (10 crafted incidents): found and fixed 2 issues — the critique prompt not seeing the incident context it was supposed to check the draft against, and a draft importing a detail (`-enc` flag) from a playbook rather than the actual incident. Both prompts now require any stated technical detail to be literally present in the incident context.

**Cost/latency** (Groq `openai/gpt-oss-120b`, 5 incidents × 2 calls): ~4–8 seconds and 2,000–3,000 total tokens per explanation. Each `/explain` costs *two* provider requests, which is why the response cache is on by default.

---

## 8. Frontend

React 19 + Vite + TypeScript + Tailwind v4 (CSS-first `@theme`), react-router 7, Recharts, Motion, lucide-react. Linted with oxlint.

### Structure

```
src/
  api/          One fetch client mirroring every backend response model
  components/   ui/ design system + feature folders (dashboard, incidents,
                chat, logs, rules, search, notifications, brand)
  context/      Auth, preferences, health, incidents snapshot, MITRE catalog, toasts
  hooks/        One data hook per screen concern
  lib/          Tokens, aggregations, filtering, formatting, navigation, polling
  layout/       Sidebar, Topbar, AppLayout shell
  pages/        One file per route
```

### Design system

All colour, type, spacing, radius, shadow and glow values are CSS custom properties in `src/index.css`, mirrored for chart libraries in `src/lib/tokens.ts`. No component contains a raw hex value.

Tailwind's JIT only sees complete class names in source, so every colour-varying utility is a literal string in a lookup map (`components/ui/accent.ts`, `lib/severity.ts`) — a class built with a template literal produces no CSS at all.

**Accent channels** (`components/ui/accent.ts`) tint a card/panel by the part of the app it belongs to: `primary` (blue-violet) for general/technical surfaces, `violet` for AI/RAG surfaces, `magenta` for telemetry/live-feed surfaces (Live Log Stream, KPI row, Pipeline Health), amber/red echoing severity, `green` reserved for genuine success states only. This is why, for example, the Dashboard's live-data panels glow pink/magenta while a settings or connection panel glows blue — it's a deliberate "which channel does this belong to" signal, not an inconsistency.

### Pages

Overview, Incidents, Incident detail, AI Assistant, MITRE ATT&CK, Alerts, Logs, Rules Engine, Reports, Settings, Demo Mode, Login. Global command palette (Ctrl/Cmd+K) searches incidents, techniques, rules, events and navigation.

### Data flow and request budget

The incidents snapshot and MITRE catalog are fetched once into context and shared; everything else is per-screen hooks. Because the API has no aggregate endpoints, all dashboard figures are computed in `lib/aggregations.ts` from those cached pages. Three background pollers exist (health, live log stream, incident snapshot) — they pause when the tab is hidden, back off exponentially when throttled, and the API client de-duplicates in-flight GETs.

---

## 9. Honesty policy

The design references this console was built against included panels a system like this cannot truthfully populate. Rather than fabricate them, each was replaced by something the data supports:

| Reference panel | What NightOwl shows | Why |
|---|---|---|
| World threat map with attack arcs | Host activity graph (hosts linked by shared techniques) | No geolocation data is ingested |
| System health: CPU/memory/disk/network | Pipeline health: API latency, rules loaded, events ingested, alerting rate | No host-telemetry collection exists; `/health` is a liveness probe |
| Assets monitored | Hosts affected (distinct hosts with an incident) | No asset inventory, only hosts that have sent telemetry |
| Percentage change "from yesterday" | Real 24h-over-24h delta, or an explicit "not enough history to compare" | Computed from ingested timestamps only when a comparable window exists |
| Signed-in user with avatar, email and role | Real single-admin session (username, sign-out) | One real admin account with a signed session cookie — see §10. No email, avatar, or multi-user roles, because none exist |
| Alert status workflow | Parent incident status | Alerts have no independent status; the incident is where status lives |
| Log storage and retention | Ingest summary (events stored, alerting, hosts, time span) | No retention policy to report |
| Enable/disable rule toggles | Read-only enabled state with an explanation | Rules are version-controlled files; no endpoint edits them at runtime |
| Threat intelligence feed | Not present at all | No feed is integrated |
| "Live" incident feed for a demo | Demo Mode (§11): a real fixture pushed through the genuine ingest → explain → chat pipeline | Nothing is generated or scripted-in-time |

Confidence figures follow the same rule: the UI shows retrieval similarity scores and the model's own self-critique result, never an invented confidence percentage.

---

## 10. Authentication

NightOwl has **exactly one admin account** — no registration, no roles, no password reset (no infrastructure for it exists). This is a deliberate scope decision, not a gap.

- **Session**: Starlette's `SessionMiddleware` issues a signed, HttpOnly, `SameSite=Lax` cookie (`itsdangerous`-backed). There is no server-side session store — the signed cookie *is* the state. Default lifetime 12 hours.
- **Credential**: `ADMIN_USERNAME` / `ADMIN_PASSWORD_HASH` (a bcrypt hash, never plaintext) in the repo-root `.env`. Empty by default, so a fresh clone has login disabled until configured.
- **Enforcement is backend-side.** `require_session_auth` (`app/core/auth.py`) is attached to every feature router alongside the pre-existing `require_api_key`. The frontend's route guards (`RequireAuth`, `RedirectIfAuthenticated`) are a UX convenience only — a request with no valid session cookie is rejected by the API regardless of what the UI shows.
- **Brute-force protection**: a separate, much smaller rate-limit bucket (5 attempts/minute by default) scoped to `POST /auth/login` only, independent of the general API rate limiter.
- **No username enumeration**: a wrong username and a wrong password return the identical `401 {"detail": "Invalid credentials."}` — the login handler compares against a fixed dummy bcrypt hash when the username doesn't match, so response shape/timing don't disclose which field was wrong.
- This coexists with, and is completely independent of, the older shared `X-API-Key` header mechanism (`require_api_key`, off by default) — two separate gates, never merged.

To generate a password hash: `./venv/Scripts/python.exe -c "import bcrypt; print(bcrypt.hashpw(b'your-password', bcrypt.gensalt()).decode())"` from `backend/`.

---

## 11. Demo Mode

Demo Mode is a one-shot, client-driven walkthrough, not a server-side simulation. As of 2026-09-08 it draws from the **real-world fixture corpus**, not a small bundled synthetic pool:

1. `GET /demo/fixtures` (`app/api/routes_demo.py`) lists every real-world fixture the *current* rule set detects — sourced live from `backend/scripts/build_failure_matrix.py`'s own `failure_matrix.json` output, so this list can never drift from the real detection ground truth. Undetected fixtures are never listed here.
2. The frontend picks one fixture via a **shuffle-bag** (`lib/constants.ts::nextDemoFixture`) — every fixture in the current pool is shown exactly once before any repeat, and the reshuffle boundary is nudged so the fixture just shown can never immediately repeat on the next click.
3. `GET /demo/fixtures/{filename}` streams the real EVTX bytes; the frontend wraps them in a real `File` and drives the exact same sequence a person would trigger by hand: `POST /ingest`, then `POST /incidents/{id}/explain`, then `POST /incidents/{id}/chat` with one scripted question. Every stage awaits a real backend round trip.

**Reset is total, not scoped.** `POST /demo/reset` deletes every row from all operational tables so fixtures can be re-ingested from a clean slate. Nothing distinguishes a demo-ingested row from a manually uploaded one, by design.

**No rebased or simulated time.** A fixture is ingested once, at real ingest time, and the resulting incident is exactly what `POST /ingest` on that file would produce for any user. (An earlier server-side "live replay" that rewrote timestamps onto a compressed wall-clock schedule was built, then removed — see §17's decision log.)

---

## 12. Setup and running

### Prerequisites

- **Python 3.10+** with a virtualenv at `backend/venv`.
- **Node 20+** for the frontend.
- **Docker Desktop** running, for PostgreSQL (`docker info` must succeed). Only the database needs it.
- Repo-root `.env`, copied from `.env.example` and filled in with a free-tier Groq key plus admin login credentials (§10).

### Windows setup issues that cost real time

| Symptom | Fix |
|---|---|
| `SSLError: CERTIFICATE_VERIFY_FAILED` reaching GitHub/HuggingFace | Corporate/AV TLS interception. `pip install pip-system-certs` once per venv. |
| `pip install -r requirements.txt` fails building `hexdump` | A python-evtx sub-dependency vs. setuptools/distutils conflict. Install with `SETUPTOOLS_USE_DISTUTILS=stdlib` set. |
| `ModuleNotFoundError` in an otherwise working venv | requirements.txt gained a dependency after the venv was created — re-run install after every pull. |

### Running the stack

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

API docs at http://127.0.0.1:8000/docs. **No `--reload`** on the backend command above by design (matches every documented workflow) — a change to `app/*.py` (not a Sigma YAML rule, which is re-parsed from disk every request) needs a manual restart to take effect.

**Rebuilding the knowledge base** (only after editing playbooks, or on a fresh clone): `python ai/tools/build_kb.py` from the repo root. First run downloads model weights and the ATT&CK bundle.

`docker compose up` brings up PostgreSQL, the backend, and a production frontend build served via nginx; for day-to-day frontend development, run the Vite dev server instead.

### Environment variables

Everything lives in the repo-root `.env`; see `.env.example` for the annotated template.

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | postgres on 5433 | SQLAlchemy connection string |
| `GROQ_API_KEY` | empty | Groq credential; missing key gives a 503, not a crash |
| `GROQ_MODEL` | `openai/gpt-oss-120b` | Model override |
| `LLM_TIMEOUT_SECONDS` | 30 | Per-call provider timeout |
| `RESPONSE_CACHE_ENABLED` | true | Route-level explain/chat cache |
| `API_KEY` | empty (auth disabled) | Optional shared secret checked as the `X-API-Key` header, alongside real login |
| `ADMIN_USERNAME` | `admin` | The one admin account's username |
| `ADMIN_PASSWORD_HASH` | empty (login disabled) | A bcrypt hash — never the plaintext password |
| `SESSION_SECRET_KEY` | empty | Signs the session cookie — treat like any other credential |
| `SESSION_MAX_AGE_SECONDS` | 43200 (12h) | Session cookie lifetime |
| `LOGIN_RATE_LIMIT_PER_MINUTE` | 5 | Failed-login throttle, `POST /auth/login` only |
| `RATE_LIMIT_PER_MINUTE` | 300 | General per-IP token bucket; 0 disables it. `/health` exempt |
| `CORS_ALLOW_ORIGINS` | localhost:5173 | Add any other origin the console is served from |
| `DEMO_MODE_ENABLED` | true | Gates all `/demo/*` routes |

Frontend variables live in `frontend/.env.local` (`VITE_API_BASE_URL`, `VITE_API_KEY`) and are baked into the bundle at build time.

---

## 13. Testing

```bash
cd backend && ./venv/Scripts/python.exe -m pytest -q     # 534 tests, 1 skipped
cd frontend && npx tsc -b && npm run build && npm run lint
```

The backend suite runs fully offline against in-memory SQLite: the shared `api_client` fixture in `tests/conftest.py` wires the real FastAPI app to a fresh database per test with `get_db`/`require_session_auth` overrides, so route tests exercise real HTTP behaviour without Postgres or a real login. `tests/api/test_auth_routes.py` is the one file that deliberately does **not** use that override, so session auth is genuinely exercised somewhere.

Tests mirror the app package layout (`tests/api`, `tests/detection`, `tests/services`, `tests/ingestion`, `tests/mitre`, `tests/rag`, `tests/core`). A few checks need network or a live database and are excluded from the offline path (RAG integration tests, anything touching Postgres or a real LLM call).

### Manual end-to-end verification

1. Start the database, backend and frontend as above.
2. Log in at `/login` with the configured admin credentials.
3. Upload `backend/sample_logs/sysmon_demo.evtx` from the Overview or Logs page — this fixture trips several loaded rules.
4. Confirm incidents appear with severities and technique ids, and Alerts/Logs/MITRE/Rules all populate.
5. Open an incident, run the AI analysis, confirm the explanation returns with source chunks, self-critique, and a Fact/Inference/Uncertainty breakdown.
6. Ask a follow-up in chat; confirm it answers and the audit trail records it.
7. Sign out; confirm every protected page redirects to `/login` and direct URL access is blocked.
8. `/demo` runs the whole ingest → explain → chat sequence end to end against a real detected fixture, with terminal narration.

---

## 14. Verifying detection accuracy

`backend/sample_logs/real_world_fixtures/` holds real, independently-sourced EVTX captures, split into three directories:

- **`detected/`** (50 files) — real attack captures the *current* rule set successfully detects.
- **`undetected/`** (11 files) — real attack captures it does not yet detect, each with a real, documented reason (see `failure_matrix.md`).
- **`benign/`** (3 files, gitignored — they carry a real owner's Windows username/hostname) — real captures from an ordinary PC, used for false-positive testing. A fresh clone just has fewer clean fixtures; nothing requires their presence.

Plus 5 synthetic `demo_fixtures/noise_*.evtx` clean slices (Sysmon-only, verified clean at generation time).

The `detected`/`undetected` split is itself this script's own **output**, recorded as a filesystem location — both benchmark scripts below scan the full corpus (both directories together) every run and re-derive the split from scratch, they never treat the current layout as an input filter:

```bash
cd backend
./venv/Scripts/python.exe scripts/run_detection_benchmark.py    # fast: aggregate recall/FP count only
./venv/Scripts/python.exe scripts/build_failure_matrix.py       # slower: full per-fixture breakdown + writes
                                                                 # scripts/failure_matrix.json/.md
```

**Current state** (re-run the scripts above for the up-to-date number): **50/61 detected (82.0%), 0 false positives** across all 8 clean fixtures. Every miss in `failure_matrix.md` is hand-classified (`channel_provider_gap`, `rule_missing`, `rule_too_narrow`, `insufficient_telemetry`, etc.) with the real field values checked, not a guessed reason — read that file before adding a new rule for a miss.

Two rules-adjacent mechanisms live outside `app/detection/rules/`: `app/detection/sequences.py` (the 3-pattern multi-event correlator, §5) and `app/services/advisory_patterns.py` (LLM second-opinion patterns). Both are read by `routes_alerts.py`/`routes_events.py`/`routes_incidents.py` alongside the loaded YAML rules when resolving an alert's title/technique.

### Verifying a specific behaviour quickly

```bash
curl http://127.0.0.1:8000/health
curl -c cookies.txt -X POST http://127.0.0.1:8000/auth/login -H "Content-Type: application/json" -d '{"username":"admin","password":"..."}'
curl -b cookies.txt "http://127.0.0.1:8000/incidents?limit=2"
curl -b cookies.txt "http://127.0.0.1:8000/events?alert_only=true&limit=3"
curl -b cookies.txt http://127.0.0.1:8000/rules | head -c 400
curl -b cookies.txt -X POST http://127.0.0.1:8000/incidents/1/explain      # costs 2 LLM requests
```

A Postman collection covering every endpoint is in `docs/postman/`.

---

## 15. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `failed to connect to the docker API` | Docker Desktop is not running | Launch it, wait ~20s, retry |
| `pg_isready` never succeeds, or port 5433 in use | Another Postgres owns the port, or the container needs more time | `docker compose ps`, `docker compose logs db` |
| First run of RAG tests or `build_kb.py` takes 1–2 minutes | sentence-transformers/ATT&CK bundle downloading | Expected once; later runs use local caches |
| Port 8000 still bound after stopping uvicorn | A reloader child process survived | `netstat -ano \| findstr :8000` then `taskkill /F /PID <pid>` |
| `POST /ingest` returns 500 with `psycopg2.OperationalError ... port 5433` | No live Postgres | Start the database |
| `POST /incidents/{id}/explain` returns 503 with rate-limit text | Groq's free-tier quota exhausted (each explain costs two requests) | Wait for the reset, or use a different `GROQ_API_KEY`. No automatic fallback provider |
| Login always returns "Invalid credentials." even with the right password | `ADMIN_PASSWORD_HASH` in `.env` wasn't actually updated, or the backend wasn't restarted after editing `.env` | Confirm the hash in `.env` matches what you generated, then restart uvicorn — env vars are read at process startup, not live-reloaded |
| A backend Python change doesn't seem to take effect | No `--reload` — a new Sigma YAML rule is re-parsed from disk every request, but anything in `app/*.py` needs a process restart | `netstat -ano \| findstr :8000`, `taskkill /F /PID <pid>`, restart uvicorn |
| Any test using `tmp_path` fails with `PermissionError: [WinError 5]` | Broken Windows temp-directory ACL | Handled automatically by `tests/conftest.py`, which redirects `--basetemp` |
| `ChatGroq(timeout=...)` appears to do nothing | The field is `request_timeout`, not `timeout` | Use `request_timeout` |

### Field note: capturing real Sysmon telemetry

Network-connection events (Sysmon Event ID 3) could not be captured on the primary dev laptop: McAfee's WFP-based firewall blocks Sysmon's network-monitoring driver. The workaround was to capture on a clean VM with a minimal ProcessCreate + NetworkConnect + FileCreate configuration.

---

## 16. Frontend data-integrity notes

A full KPI/chart audit (2026-09-08) cross-referenced every stat card, donut, and chart across all 10 pages against direct database/API ground-truth queries. Ground truth confirmed at audit time: 32,646 events · 170 alerts · 45 incidents · severities 15/23/4/3 (critical/high/medium/low) · 45 loaded rules · 28 distinct MITRE techniques observed. Nearly every number matched exactly. Real bugs found and fixed along the way (all since resolved):

- **Historical-timestamp display**: `formatRelativeTime`/`formatDuration` now cap at 30 days and fall back to absolute dates, instead of showing "47,000 hours ago" for old fixture data.
- **Dashboard/Logs/Reports time-window bugs**: several charts and `buildReport()` were anchoring "recent activity" windows to `Date.now()` instead of the dataset's own latest timestamp — meaningless against fixture data with old timestamps. Fixed via `lib/aggregations.ts::activityAnchorMs()`, which anchors to real dataset time everywhere.
- **Mislabeling**: "Detection rate"/"Detection ring" renamed to "Alerting event rate"/"Alerting" where the number actually measures alert generation, not ground-truth detection accuracy (that number lives in `failure_matrix.md`, §14).
- **Capped severity tallies**: Incidents/Dashboard severity breakdowns were tallying a client-side array capped at 1,000 rows instead of using dedicated ground-truth queries — fixed by adding `totalHigh`/`totalMedium`/`totalLow` (alongside the existing `totalCritical`) to the incidents snapshot, each backed by its own `GET /incidents?severity=X&limit=1` count query.
- **Missing tactics**: see §6 — `stealth`/`defense-impairment` were entirely absent from the frontend's tactic vocabulary, silently hiding every technique whose only real tactic was Defense Evasion from every tactic-based view.
- **MITRE donut silently capped at top 6 tactics** with no "Other" bucket, undercounting the total the moment a corpus produced a 7th active tactic. Fixed with the same top-6-plus-"Other" convention used elsewhere.

---

## 17. Decision log

One entry per significant decision. Every one names its alternative and whether it is reversible.

**LLM provider: Groq-only (2026-09-06, superseding an earlier Gemini/Groq dual setup).** Gemini's free tier proved structurally unreliable (hard 20-req/day quota, separate server-side overload). The dual-provider branch was fully removed rather than left dormant. No automatic fallback exists or is planned. Reversible via git history, but re-adding support means re-adding the whole branch.

**pySigma for validation, own evaluator for matching.** See §5. Reversible: only `rule_loader` and `engine` know about it.

**Rules match raw Sysmon field names, not a normalized schema.** Portability from public Sigma sources beats an invented vocabulary. Reversible: `event_data` is additive.

**Severity combines Sigma level with MITRE tactic weight.** Both read from the rule's own tags; rules with no tactic tag contribute zero weight.

**Structured logging is a 30-line stdlib JSON formatter**, not structlog/python-json-logger — the requirement was structured logs, not an observability stack.

**Rate limiting is a per-IP token bucket, `/health` exempt, 300/min ceiling.** A single dashboard paint legitimately costs about a dozen requests; the original 60/min throttled ordinary use.

**Reports and Settings are client-side by design.** No reports table, no settings endpoint — Reports generates its document live from API data, Settings stores genuinely local browser preferences.

**Live SOC replay was built, then removed in favour of one-shot Demo Mode.** A server-side thread that rewrote real captures onto a compressed wall-clock schedule worked, but was a second, parallel demo code path carrying its own bug class for a "live" feel a straightforward real upload already delivers honestly. Reversible: recoverable from git history, and the shared `ingest_records()` path was never coupled to it.

**Single-admin session auth, not multi-user/RBAC (2026-09-08).** NightOwl has one operator; building account management, roles, or team features for a single-admin deployment would be unused complexity. Real, backend-enforced login (signed HttpOnly cookie) was still built — "no accounts" does not mean "no real authentication." See §10.

**Demo Mode rebuilt to draw from the real-world fixture corpus instead of a small bundled synthetic pool (2026-09-08).** The earlier pool was 7 hand-sliced/generated fixtures committed into the frontend's static bundle (~16MB). Replaced with `GET /demo/fixtures`, sourced live from the same `failure_matrix.json` this project's own detection-accuracy tracking already produces — one source of truth instead of two, and every fixture Demo Mode can show is provably one the current rule set actually detects. The tooling that built the old synthetic pool (`build_demo_evtx_fixtures.py`, `generate_missing_rule_events.ps1`) was removed as dead code once nothing referenced it any more.

**Real-world fixture corpus split into `detected/`/`undetected/`/`benign/` (2026-09-08, previously `malicious/`/`benign/`).** Makes which fixtures the current rule set catches visible directly in the repository's own file layout, not just in a generated report. Both benchmark scripts still scan the full corpus every run and treat the split as their own output, never as an input filter — a rule change that flips a fixture's status is picked up automatically the next time `build_failure_matrix.py` runs and re-sorts it.

---

## 18. Vision and deliberate scope boundaries

NightOwl's original planning document (`final_plan.md`, now folded into this history) laid out an 18-phase long-term vision. Phases actually built are documented throughout this file. A few were deliberately **not** built, and stay that way on purpose — building ahead of real evidence is exactly the mistake this project corrected twice during development (see the KPI/timestamp bugs in §16, both caused by earlier code that assumed "now" instead of checking the data):

- **Evidence graph** (relating incidents/hosts/accounts visually) — every incident in the real corpus is single-host with no demonstrated need for a relationship model. Both of its prerequisites (evidence-first alerts, the investigation timeline) already shipped; this is blocked on a real graph-shaped need showing up in a future failure-matrix run, not before.
- **Multi-host campaign correlation** — zero fixtures in the corpus currently show cross-host activity. If ever built: never correlate on shared username/IP alone, require multiple meaningful signals.
- **Real-time architecture (Kafka/Redis/WebSockets)** — explicitly not worth building for an EVTX upload system ahead of a real need for it.
- **Threat-intel feeds, a geographic attack map, host CPU/memory/disk telemetry** — nothing in the system could honestly populate them (§9).
- **User registration, multiple users, RBAC, OAuth/social login, email verification, password reset** — a single-admin deployment doesn't need them; see §10 and its decision-log entry.

**Detection accuracy timeline** (each step measured against the real fixture corpus, never estimated): 3/32 (9.4%) → 18/32 Sysmon-coverage pass → 24/32 Security-channel pass → 26/39 after the corpus grew → 31/39 after 4 evidence-driven rules → 33/39 after the sequence engine → 47/54 after the corpus grew again plus 6 new rules (including PowerShell-channel support) → 50/61 after the corpus grew a final time plus 2 more rules. Rule count grew alongside it: 15 → 33 → 39 → 41 → 43 → **45**. Throughout, false positives held at **0** across a growing clean corpus (5 synthetic → 8, once real Security, PowerShell, and Sysmon-only clean captures were added). A second-pass deep audit (2026-09-08) reviewed every one of the 11 remaining misses' real field values and found zero further rules were justified — each is either genuinely inconclusive or has real evidence with too few samples to safely generalize, below this project's own ≥3-sample bar for threshold-based rules.

---

## 19. Working conventions

- **Commits** follow Conventional Commits (`feat:`, `fix:`, `chore:`, `docs:`, `test:`, `style:`), one line, describing the behaviour change rather than the file touched.
- **Layering** is enforced by review: routes compose services, services own database access, models stay dumb.
- **Comments explain why, not what.** Every non-obvious decision carries the reasoning and the alternative that was rejected — §17 is the long form of the same habit.
- **Tests mirror the package they cover.**
- **Nothing that cannot be backed by real data ships to the UI.** If a panel cannot be populated honestly, it is replaced by one that can (§9).
- **Free-tier only.** No paid API is used anywhere, which is why LLM quota management (caching, two-call awareness) is a design concern rather than an afterthought.
- **Measure before building.** Every detection rule in this project was added because a real fixture proved a real gap — never speculatively. Re-run `run_detection_benchmark.py`/`build_failure_matrix.py` after any detection-affecting change; that number, not a document, is the source of truth.

---

## 20. Team

A 4-person team, working as two rotating pairs across backend, AI/RAG, and frontend tracks, swapping tracks in the frontend phase so everyone touches at least two of the three layers. Built AI-assisted over a 30-day roadmap (compressed to 26).
