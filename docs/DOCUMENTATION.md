# NightOwl — Documentation

How NightOwl is built and why, how to run, deploy and test it, and how it got here. This is the single reference document for the project. The ML anomaly layer has its own file, [`ML.md`](../ML.md).

Every figure quoted here comes from a script in `backend/scripts/` whose output is checked in next to it. When a figure here disagrees with that output, trust the output.

---

## 1. What NightOwl does

NightOwl turns Windows event-log exports (EVTX) into a small number of prioritised, explained incidents. It is not "a SOC platform that detects every attack", because no static EVTX analyser can honestly promise that. It is an evidence-driven investigation tool:
- it profiles the uploaded telemetry;
- it detects known malicious behaviours and maps them to MITRE ATT&CK;
- it explains each incident with a retrieval-grounded LLM;
- it says what the available telemetry cannot determine.

```
EVTX upload (one file = one channel)
   |
   v
Ingestion     evtx_reader -> normalizer -> NormalizedEvent        --> events
   |          (de-duplicated by host + channel + EventRecordID)
   v
Detection     69 Sigma-style YAML rules, per event
              + 11 multi-event sequence detectors, per batch      --> alerts
   |          severity = Sigma level + ATT&CK tactic weight
   |          repeat matches (same rule/host/process, 60 s) fold into one alert
   v
Correlation   detections grouped per host, sliding 1 h window     --> incidents
   |
   +--------  ML anomaly layer (advisory): unusual 10-min windows
   |          recorded as evidence, never as detections           --> alerts (kind=ml)
   v
AI layer      retrieve (ChromaDB) -> draft (LLM) -> self-critique (LLM)
   |          explanation + Fact/Inference/Uncertainty + response + sources
   v
Console       React SOC UI over the REST API, behind an admin login
```

Every number the console shows comes from this pipeline. Nothing is simulated.

---

## 2. Repository layout

```
├── backend/        FastAPI service: API routes, detection engine + rules, ingestion,
│                   ATT&CK mapping, incident/severity services, RAG runtime (app/rag),
│                   ML anomaly layer (app/ml), models, Alembic migrations, tests,
│                   sample logs and measurement scripts
├── frontend/       React + Vite + Tailwind SOC console (nginx in Docker)
├── ai/             RAG knowledge base (playbooks), vector store, KB build tooling
├── docs/           This file, Postman collection
├── ML.md           ML anomaly layer: design, evaluation, limits
└── docker-compose.yml
```

The RAG *runtime code* lives in `backend/app/rag/` because the API imports it directly. `ai/` holds the corpus, the vector store and the tooling that builds them.

**Backend layering rule:** routes → services → models/db. Only the service layer talks to the database. Routes compose services and own their Pydantic response models.

---

## 3. Data model

PostgreSQL 16, SQLAlchemy 2 declarative models, Alembic migrations (applied automatically by the Docker entrypoint).

| Table | Key fields |
|---|---|
| `events` | `id`, `host` (upper-cased), `timestamp` (UTC), `event_id`, `channel`, `event_record_id`, `process`, `parent_process`, `command_line`, `user`, `raw_json` |
| `alerts` | `id`, `event_id` → events, `rule_id`, `matched_at`, `severity`, `severity_score`, `incident_id`, `occurrence_count`, `last_matched_at`, `details` (JSON; ML evidence) |
| `incidents` | `id`, `title`, `status`, `severity`, `severity_score`, `host`, `mitre_technique_ids` (JSON), `created_at`, `last_activity_at` |
| `chat_messages` | `id`, `incident_id`, `role`, `content`, `created_at` |
| `audit_log` | `id`, `entity_type`, `entity_id`, `action`, `actor`, `details`, `created_at` |
| `ai_opinions` | `id`, `filename`, `created_at`, `status`, `assessment_label`, `summary`, `sample_event_ids`, `limitations`, `attack_candidate_ids`, `error` |
| `admin_sessions` | `id`, `username`, `created_at`, `expires_at`, `revoked_at` |

`raw_json` stores both the original record and the normalized view, so fields the normalizer does not promote to columns (Hashes, the network 5-tuple) are never lost. Over-long values are clipped to their column size instead of failing the whole file.

The rule `rule_id` is either a Sigma rule UUID, a `sequence-*` id or `ml-anomaly-detector`. `app/detection/synthetic.py` resolves the last two, since they have no YAML file.

**Severity vocabulary**, shared by backend, API and UI: `informational | low | medium | high | critical`.

---

## 4. API surface

All routes are mounted at root. `/health` is public. Every other route requires a valid admin session **or** the `X-API-Key` header when `API_KEY` is set (for scripts and CI). State-changing requests must also carry the CSRF header (§10).

| Method | Path | Notes |
|---|---|---|
| GET | `/health` | Liveness only. Public, exempt from rate limiting |
| GET | `/system/status` | Readiness of the LLM key, knowledge base, rules, ML bundle, ATT&CK dataset; demo flag |
| POST | `/auth/login` | Admin login; creates a server-side session |
| POST | `/auth/logout` | Revokes the session |
| GET | `/auth/me` | Current session's username, or 401 |
| POST | `/ingest` | multipart `.evtx` upload (default cap 100 MB), synchronous: counts (checked / everyday / unchecked), notices, telemetry profile, incident ids, ML anomalies, AI opinion id |
| POST | `/ingest/async` | same upload, processed in the background: returns `202 {job_id}` at once (the console uses this so a multi-minute parse never hits a browser timeout) |
| GET | `/ingest/jobs/{id}` | job status (`reading` -> `analysing` -> `done` / `failed`), records read so far and, when done, the same payload `POST /ingest` returns. Jobs live in memory for an hour |
| | | The status also carries `records_total`, `elapsed_seconds` and `eta_seconds`, which the console shows as "Reading N of M records (x%) - about Ns left" |
| GET | `/mitre/techniques` | ATT&CK Enterprise catalog |
| GET | `/incidents` | `severity`, `status`, `start_date`, `end_date`, `q`, `limit` (≤200), `offset` |
| GET | `/incidents/{id}` | Incident, alerts and events, resolved techniques |
| PATCH | `/incidents/{id}/status` | open, investigating, resolved, closed; writes an audit row with the session user |
| GET | `/incidents/{id}/audit` | Audit trail |
| POST | `/incidents/{id}/explain` | RAG explanation + recommended response + source chunks |
| POST/GET | `/incidents/{id}/chat` | Incident-scoped chat turn (≤4,000 chars) / history |
| GET | `/alerts` | `host`, `start_date`, `end_date`, `severity`, `q`, `kind` (`detection` or `ml`), `limit`, `offset` |
| GET | `/ai-opinions/{id}` | Advisory AI review of an upload's unchecked events |
| POST | `/ai-opinions/{id}/retry` | Re-run a failed review (for example after the free-tier rate limit resets) |
| GET | `/ml/model` | The anomaly layer's mode, training date, machines and windows per log family, thresholds and held-out false-alarm rates |
| GET | `/events` | `host`, `start_date`, `end_date`, `alert_only`, `severity`, `q`, `covered`, `coverage`, `limit`, `offset` |
| GET | `/events/{id}` | One event including `raw_json` |
| GET | `/rules`, `/rules/{rule_id}` | Sigma rules, sequence detectors and the ML entry (`kind`), with match counts |
| POST | `/demo/reset` | Deletes all operational rows and clears the response cache |
| GET | `/demo/fixtures` | Attack captures the current rules detect with the correct technique |
| GET | `/demo/fixtures/{filename}` | Streams one fixture |

The `/demo/*` routes also need `DEMO_MODE_ENABLED=true`. `/docs` and `/openapi.json` exist only when `APP_ENV=local`.

Error shape is uniform: `{"detail": ...}`. An LLM provider failure gives 503 with a sanitised reason, a throttled request gives 429, an oversized upload gives 413 and a missing CSRF header gives 403. Lists are newest-first with an `id` tiebreak. Dashboard aggregates are computed client-side. Live data is polled, not streamed.

---

## 5. Detection engine

### Sigma-style rules

The rules are 66 YAML files in `backend/app/detection/rules/`, loaded once per process and cached. Restart the backend after you change a rule.

- **pySigma validates; NightOwl evaluates.** pySigma converts rules into query languages for external log stores and has no backend for matching one in-memory event. So `SigmaRule.from_yaml()` validates each rule's structure and `engine.py` evaluates its `detection` block.
- **Supported subset:**
  - named selections (AND across fields, OR across a value list) and lists of selections;
  - the modifiers `contains`, `startswith`, `endswith`, `re`, `cidr`, the flags `all` and `windash`, `*`/`?` wildcards and `null`;
  - conditions with `and`/`or`/`not`, parentheses, `1 of`/`all of` over a name pattern or `them`.

  Conditions are parsed by a recursive-descent parser, never `eval()`. Field matching is case-insensitive.
- **Strict loading.** A rule is rejected at load time, never loaded half-working, when:
  - it uses an unsupported modifier;
  - its condition cannot be parsed or refers to an undefined selection;
  - its logsource category is not scoped to known `(channel, event id)` pairs;
  - its ATT&CK tactic tags do not belong to its technique in ATT&CK v19.2.
- **Field names are the raw Windows/Sysmon ones** (Image, CommandLine, TargetUserName). SigmaHQ rules that stay inside the supported subset and a scoped category can be adapted. Others, such as those using aggregations, `near` or unsupported modifiers, need rewriting.
- **Channel coverage** (rules per service): Sysmon 36, Security 23, PowerShell script-block 4104 3, System 1, Application 1, RPC trace 1, BITS 1. PowerShell module logging (4103) is classed as everyday activity; the script text is judged from 4104.

### Sequence detectors

`detection/sequences.py` holds 11 multi-event detectors. They run once per ingest batch and feed the same alert path:

| Detector | Technique |
|---|---|
| Process Herpaderping: FileCreate → ProcessAccess → ImageLoad on one ProcessGuid | T1055 |
| SMB share-enumeration probe | T1135 |
| SMB fan-out: one process opens port-445 connections to 5 or more distinct hosts within 60 s | T1018 |
| Named-pipe sweep: one process connects to 8 or more distinct RPC pipes within 5 s (verified on the real discovery capture: 14 pipes in half a second) | T1018 |
| Kerberos password spray: failed pre-auth across many accounts from one source | T1110.003 |
| Authentication brute force: repeated failures against one account | T1110 |
| Remote SAM/LSA enumeration | T1087 |
| Mass process access | T1057 |
| Group self-add | T1098 |
| Bulk group-membership addition | T1098 |
| SYSTEM process started by a parent running as another account (token theft, the end state of the "potato" family and PrintSpoofer). A parent whose account is unknown is never guessed at | T1134.002 |

`SEQUENCE_PATTERNS` holds each detector's thresholds and rationale.

### What an upload says: checked, everyday, unchecked

Every event type (channel + event id) in a file is sorted by `detection/coverage.py`:

| Kind | Meaning | Examples |
|---|---|---|
| **Checked** | A Sigma rule, a sequence detector or the notice generator evaluates it | Sysmon 1/3/10/11, Security 4625/4768/4771, System 7045, the EFSRPC RPC call |
| **Everyday** | Routine operating-system activity that no attack rule needs | Security 5379 credential-manager reads, 4672, 4634; Sysmon 5 process exit; System and Application operational events; PowerShell engine start/stop |
| **Unchecked** | Security-relevant or unknown, and nothing evaluates it | Security 5136, Sysmon 22, events on an unrecognised channel |

The "everyday" lists were measured on the benign corpus; each entry carries its reason in `coverage.py`. The verdict (`frontend/src/lib/verdict.ts`, mirrored by `backend/scripts/upload_sweep.py`):

- a rule or detector matched -> **Suspicious activity detected**;
- no match, but unchecked events or an advisory pattern -> **Review recommended**;
- no match, everything checked or everyday -> **Normal -- no threats detected**.

The AI review only ever reads *unchecked* events and advisory-pattern events, so a benign file with nothing unchecked makes no AI call. A System 104 "log cleared" event is reported as an informational **notice** naming the account and log (read from the event's `UserData`); it opens no alert. The Security-log equivalent (1102) remains a detection. `GET /events` accepts `coverage=checked|routine|unchecked` for the same three-way split.

Three guards keep the review from contradicting or embellishing a detection: (1) every sampled event carries a real name looked up by channel and id, and a known RPC interface carries its service name (`detection/event_names.py`), so the model never has to guess what a number or UUID means; (2) when a pipe-based sequence detector fires on a host, that host's other named-pipe events are not sent for review, because they are the same burst; (3) when the file already has rule detections, technique documents are withheld from the review's retrieved context, so it describes the leftover events in plain words and the technique comes from the detections.

### Severity, de-duplication and grouping

- **Severity** (`services/severity_service.py`): the Sigma level rank (1–5), plus 1 if the rule is tagged with a high-leverage tactic (credential access, lateral movement, collection, command and control, exfiltration, impact), capped at critical.
- **Alert de-duplication:** a repeat match of the same rule, host and process within 60 s increments `occurrence_count` on the existing alert instead of creating a new one.
- **Incident grouping** (`services/incident_service.py`): a detection joins an *open* or *investigating* incident on the same host whose activity span lies within 1 hour of it. The window slides with `last_activity_at`. The incident takes the union of technique ids and the higher severity, and its title follows its most severe alert. Otherwise a new incident is opened. Ingest takes a per-host advisory lock, so two concurrent uploads for one host cannot open duplicate incidents.
- **Incident titles**: an incident is titled after its most severe detection, with one exception. A cover-up detection (the T1685 family: a cleared audit log, a weakened audit policy) never headlines an incident that also holds the attack itself; it still raises severity and adds its technique.

### Outside the rule engine

- **Advisory patterns** (`services/advisory_patterns.py`) are event shapes too false-positive-prone to alert on, such as `System` connecting to `\lsass`/`\srvsvc`. They are routed to the AI second opinion and never create alerts.
- **The ML anomaly layer** (`app/ml/`) has per-log-family models over 10-minute windows. It is **experimental** and runs in **advisory mode** by default (retraining on more machines is deferred to future work, 19 October 2026): it records anomalies with the features behind each one and links them to an existing incident, but never opens one and never counts as a detection. On a familiar machine it produces 1–4.5 false windows per host-day, and it does not transfer to unseen machines. Full design and evaluation: [`ML.md`](../ML.md).

---

## 6. MITRE ATT&CK mapping

- ATT&CK Enterprise **v19.2** ships as a trimmed index at `backend/app/mitre/data/enterprise_attack_v19_2.json.gz`. Nothing is downloaded at runtime. `rebuild_index()` regenerates it from a full STIX bundle.
- Per technique: id, name, description, tactics, deprecated/revoked flags.
- ATT&CK v19 has no `defense-evasion` tactic. It is split into `stealth` and `defense-impairment`. Rule tags use the underscore form (`attack.defense_impairment`), and the frontend's tactic order includes both.
- **Tags must be consistent.** A technique id that does not exist, or a tactic tag that does not belong to the rule's technique, rejects the rule at load (§5).

---

## 7. AI / RAG layer

### Corpus and retrieval

`ai/tools/build_kb.py` chunks the ATT&CK technique descriptions (skipping deprecated and revoked ones) and the playbooks in `ai/knowledge_base/playbooks/`. Chunks are 800 characters with 100 characters of overlap. They are embedded with sentence-transformers `all-MiniLM-L6-v2` into one ChromaDB collection in `ai/vector_store/`.

Retrieval is top-k (k=5), filtered to the incident's techniques *and their parent techniques* (T1003.001 also retrieves T1003). An empty knowledge base is logged and reported by `/system/status`.

### Generation

`rag/explain_service.py` runs **retrieve, draft, self-critique**. One LLM call drafts the explanation from the incident evidence and the retrieved chunks. A second call checks the draft against both, and any flagged claims are appended as a confidence-check block. Every explanation carries a **FACT / INFERENCE / UNCERTAINTY** breakdown parsed from a required section.

Chat (`rag/chat_service.py`) is one call per turn without a critique pass. A turn is stored only after the LLM answers, so a failed call leaves no orphan message.

### Prompt safety

All log-derived text is untrusted. Process names, command lines, users and similar fields are truncated and placed inside fences marked with a random per-request nonce (`rag/safety.py`). The system prompt tells the model to treat fenced text as data, never as instructions.

The AI second opinion's verdict is read only from a strict heading line. Any ATT&CK id in model output that does not exist in the dataset is annotated as unverified.

### What the model sees

`incident_service.build_incident_evidence()` builds the evidence from:
- the incident's primary *detection* alert, which is the detection the incident is titled after (falling back to the earliest detection): process, parent, command line, user, rule title, method, time and source;
- every technique id with its official ATT&CK v19.2 name (`techniques`), because the model does not know ids introduced after its training;
- **the detection event's own fields** (`event_details`): up to 15 "Name: value" lines, each at most 240 characters, with identifiers that mean nothing to an analyst (GUIDs, logon and process ids, UtcTime) removed;
- up to 5 nearby events on both sides of it, each with its key fields (destination address and port, file, registry key and value, pipe, service, account, share, task);
- any ML anomalies, listed separately as supporting statistics.

An ML record is never chosen as the primary alert. Before 19 October 2026 the evidence carried only process, parent, command line and user, and for network, file and registry detections the explanation reported the destination, file or registry value as "not in the evidence" (§7 Evaluation).

### Provider, caching, failure

- **Groq only**, behind `rag/llm_client.py`. There is no silent fallback, so an outage surfaces as a 503 carrying a sanitised reason. Provider error bodies are not echoed.
- **Route-level response cache:** on by default with a 900 s TTL. It is keyed on the incident id *and* its evidence (alert count and latest alert), so new detections invalidate it. Demo reset clears it.
- **Optional prompt-hash cache** in `llm_client`, off by default.
- **Bounded requests:** chat sends at most the last 10 messages, each earlier turn shortened to 1,200 characters and the history as a whole to 4,000 (newest kept first); evidence is rendered with tighter limits in chat (command line 1,200 characters, other fields 500, each related event 400). The worst case is about 4,500 tokens, under the free Groq tier's 8,000-token-per-minute ceiling that one unbounded follow-up exceeded (8,012 tokens). `tests/rag/test_prompt_size.py` checks it.
- **Retries:** one retry, on retryable errors only (timeouts, 5xx). A per-minute rate limit (429) is retried once after the provider's own suggested wait when that wait is 30 s or less; a longer one (the free tier's 200,000-token daily quota) fails at once and the console shows the real wait ("try again in about 13 minutes").

### AI second opinion guards

The second opinion reviews only *unchecked* and advisory-pattern events (§5). Five guards, each added after a measured failure in the 10 October fixture audit:
- every sampled event carries a verified name looked up by channel *and* event id, and a known RPC interface carries its service name from Microsoft's open protocol specifications (`detection/event_names.py`), so the model never guesses what a number or UUID means;
- the prompt forbids identifying an unnamed identifier and forbids guessing what a listed detection matched;
- when a pipe-based sequence detector fires on a host, that host's other named-pipe events are not sent;
- when the file already has rule detections, technique documents are withheld from its retrieval;
- a candidate ATT&CK technique is offered only above a retrieval score of 0.55 (measured: 23-42% of candidates correct at 0.50, all correct at 0.55).

### Evaluation (measured, not assumed)

The full numbers, with before/after tables, are in `docs/PAPER_MATERIAL.md` §5.4.

- **Knowledge-base coverage:** all 50 ATT&CK techniques NightOwl can emit have their own chunks (1,888 chunks: 1,872 ATT&CK, 16 playbook).
- **Unfiltered retrieval from raw events** (61 labelled captures): the expected technique is in the top 3 for 13 of 61 captures from the events alone, 21 of 61 with the file name. This is why the technique comes from the rules and retrieval is filtered to it.
- **Explanations** (10 crafted incidents, real LLM): every key fact stated correctly after the evidence fix, against 6 of 10 before.
- **Chat:** refuses facts the evidence does not hold, declines off-topic requests, and ignored a prompt injection planted in an event's command line.

**Retrieval quality, earlier check** (10 queries): 9 out of 10 returned the correct playbook or technique in the top 3. The miss was a vocabulary gap: "beaconing" never appears in the C2 playbook.

**Hallucination spot-check** (`ai/tools/hallucination_spot_check.py`, 10 crafted incidents) found two issues, both fixed:
- the critique pass could not see the incident evidence;
- a draft imported an `-enc` flag from a playbook into an incident that had none.

The script runs against an in-memory database and never writes to the real one.

**Cost and latency** (Groq `openai/gpt-oss-120b`): about 4–8 s and 2,000–3,000 tokens per explanation. Each `/explain` makes two provider calls.

---

## 8. Frontend

React 19 + Vite + TypeScript + Tailwind v4 (CSS-first `@theme`), react-router 7, Recharts, Motion and lucide-react, linted with oxlint.

### Structure

```
src/
  api/          One fetch client mirroring every backend response model
  components/   ui/ design system + feature folders (dashboard, incidents,
                alerts, chat, logs, rules, search, notifications, brand)
  context/      Auth, preferences, health, incidents snapshot, MITRE catalog, toasts
  hooks/        One data hook per screen concern
  lib/          Tokens, aggregations, filtering, formatting, navigation, polling
  layout/       Sidebar, Topbar, AppLayout shell
  pages/        One file per route
```

### Design system

All colour, type, spacing, radius, shadow and glow values are CSS custom properties in `src/index.css`. They are mirrored for chart libraries in `src/lib/tokens.ts`, and no component contains a raw hex value. Colour-varying utilities are literal strings in lookup maps (`components/ui/accent.ts`, `lib/severity.ts`), because Tailwind's JIT cannot see class names built with template literals.

Accent channels tint a surface by the part of the app it belongs to:
- `primary` for general and technical surfaces;
- `violet` for AI/RAG surfaces;
- `magenta` for telemetry surfaces;
- amber and red echo severity;
- `green` is reserved for real success states.

### Pages

Overview, Incidents, Incident detail, AI Assistant, MITRE ATT&CK, Alerts (Detections and *ML anomalies, experimental* in separate views), Logs, Rules Engine, Reports, Settings (with live `/system/status`), Demo Mode and Login. A global command palette (Ctrl/Cmd+K) searches incidents, techniques, rules, events and navigation.

### Data flow

The incidents snapshot and the MITRE catalog are fetched once into context. Everything else comes from per-screen hooks. Dashboard figures are computed in `lib/aggregations.ts`, anchored to the dataset's own latest timestamp rather than "now".

Background pollers pause while the tab is hidden and back off when throttled. The client de-duplicates in-flight GETs and sends the CSRF header on every mutation. Signing out resets every session-scoped provider and module cache.

Event labels are channel-aware: Sysmon names are shown only for Sysmon events, because Security 1 and System 1 mean different things.

---

## 9. Honesty policy

Panels that a system like this cannot truthfully populate were replaced by something the data supports:

| Typical SOC panel | What NightOwl shows | Why |
|---|---|---|
| World threat map | Host activity graph (hosts linked by shared techniques) | No geolocation data is ingested |
| Host CPU/memory/disk | Pipeline health: API latency, rules loaded, events ingested, alerting-event rate | No host telemetry; `/health` is liveness only |
| Assets monitored | Hosts affected | No asset inventory |
| "% from yesterday" | Real 24 h-over-24 h delta, or "not enough history" | Computed only when a comparable window exists |
| User profile, roles | Single-admin session (username, sign-out) | One admin account (§10) |
| Alert status workflow | Parent incident status | Status lives on the incident |
| Rule enable/disable toggles | Read-only state | Rules are version-controlled files |
| Threat-intel feed | Not present | None is integrated |
| "Live" demo feed | Demo Mode: a real capture through the real pipeline (§11) | Nothing is scripted in time |
| "AI detected" | ML anomalies labelled *experimental, not a detection* | The model is not accurate enough to assert attacks (ML.md) |

Confidence is never an invented percentage. The UI shows retrieval similarity scores, the self-critique result and, for ML anomalies, the actual distance, thresholds and contributing features.

---

## 10. Authentication and security model

NightOwl has **one admin account**: no registration, no roles, no password reset. This is a deliberate scope decision.

**Login and sessions**
- **Credential:** `ADMIN_USERNAME` and `ADMIN_PASSWORD_HASH`, a bcrypt hash, never plaintext. Passwords longer than 72 bytes are rejected with 401, not a 500.
- **Session:** a signed, HttpOnly, `SameSite=Lax` cookie (`Secure` outside local) that references a row in `admin_sessions`. Logout sets `revoked_at`, so a copied cookie stops working immediately. The default lifetime is 12 h.
- **Startup checks:** outside `APP_ENV=local` the backend refuses to start when:
  - `SESSION_SECRET_KEY` is missing or shorter than 32 characters;
  - `ADMIN_PASSWORD_HASH` is missing or not a bcrypt hash;
  - the database password (in `DATABASE_URL`) is shorter than 12 characters or an example value such as `nightowl`.
- **Audit trail:** every successful, failed and throttled login and every logout is written to `audit_log` (`entity_type="auth"`) and to the log with the client IP. A failed attempt records the actor as the admin name only when that was the name typed, otherwise `unknown`, so a password typed into the username box is never stored. `POST /demo/reset` clears `audit_log` along with the other operational tables.

  In local mode a random secret is generated per process.

**Request protection**
- **CSRF:** every state-changing request must carry `X-NightOwl-Request: 1`. A cross-site form cannot set a custom header, and a cross-origin script cannot without a CORS preflight, which only the configured origins pass.
- **Brute force:** failed logins are throttled per client (5 per minute by default). Successful logins do not count against the limit.
- **No username enumeration:** a wrong username and a wrong password return the identical 401. The handler checks a dummy hash, so timing matches as well.
- **Enforcement is in the backend.** Frontend route guards are only a UX convenience.

**Other safeguards**
- **Upload guard:** a pure-ASGI middleware rejects an oversized body by `Content-Length` and by a running byte count, before any route reads it.
- **One upload at a time:** `MAX_CONCURRENT_INGESTS` (default 1) uploads are processed at once; another `POST /ingest` or `/ingest/async` meanwhile gets **409** "Another upload is still being processed". Each upload holds its records in memory and can start up to 16 reader processes, and two large ones at once ran a 16 GB machine out of memory.
- **Rate limiting:** a per-IP token bucket (300 per minute) with `/health` exempt. Client IPs are taken from proxy headers only from `TRUSTED_PROXIES`.
- **Exports:** CSV cells starting with `= + - @` are neutralised against formula injection.

To generate a password hash, run this from `backend/`:

`./venv/Scripts/python -c "import bcrypt; print(bcrypt.hashpw(b'your-password', bcrypt.gensalt()).decode())"`

---

## 11. Demo Mode

Demo Mode is a client-driven walkthrough over the real pipeline:

1. `GET /demo/fixtures` lists the attack captures the current rules detect **with the correct technique**. The list is read from `backend/scripts/failure_matrix.json`, the output of `build_failure_matrix.py`, so it cannot drift from measured results.
2. The frontend picks one from a shuffle-bag: every fixture is shown once before any repeats, and the same one never appears twice in a row.
3. It downloads the fixture and runs the same sequence a person would: `POST /ingest`, then `POST /incidents/{id}/explain`, then one `POST /incidents/{id}/chat` question.

`POST /demo/reset` deletes all operational rows (events, alerts, incidents, chat, audit, AI opinions) and clears the response cache. Fixtures keep their real timestamps; nothing is rebased.

The Docker image includes the fixtures and `failure_matrix.json`, so Demo Mode works in a container.

---

## 12. Setup, deployment and configuration

### Docker (recommended, also the production path)

```bash
cp .env.example .env
# set ADMIN_PASSWORD_HASH, SESSION_SECRET_KEY (32+ chars), a strong
# POSTGRES_PASSWORD (12+ chars, also in DATABASE_URL), GROQ_API_KEY
docker compose up --build -d
```

The backend container always runs with `APP_ENV=production` (hard-coded in `docker-compose.yml`, never taken from `.env`), so `/docs` is hidden, the session cookie is `Secure`, and the startup checks in §10 apply. Browsers accept a `Secure` cookie on `http://localhost` and `http://127.0.0.1`, so local use works without TLS.

- **db:** PostgreSQL 16, bound to `127.0.0.1:5433` only, with a named volume. Compose refuses to start without `POSTGRES_PASSWORD`. Changing `POSTGRES_PASSWORD` later does not change an existing database's password: run `ALTER USER nightowl PASSWORD '...'` in the db container as well.
- **backend:** the entrypoint runs `alembic upgrade head` and builds the knowledge base on first start (this needs network access once; set `NIGHTOWL_BUILD_KB=0` to skip). It then starts uvicorn. The knowledge base and the model cache live in named volumes, and a healthcheck polls `/health`.
- **frontend:** a production build served by nginx with security headers, on http://localhost:5173.

### Network access

The API (8000) and console (5173) are bound to `127.0.0.1` by default (`API_BIND` / `UI_BIND`), because both speak plain HTTP: on a network they would carry the admin password and session cookie in clear text, and the `Secure` cookie would not be sent at all. To use NightOwl from another machine, put a TLS-terminating reverse proxy in front instead of binding to `0.0.0.0`. For example, a Caddy service serving one origin:

```
nightowl.example.lan {
  header Strict-Transport-Security "max-age=31536000; includeSubDomains"
  handle_path /api/* { reverse_proxy backend:8000 }
  reverse_proxy frontend:80
}
```

Then build the frontend with `VITE_API_BASE_URL=https://nightowl.example.lan/api`, set `CORS_ALLOW_ORIGINS` to that origin, and set `TRUSTED_PROXIES` / `FORWARDED_ALLOW_IPS` to the proxy's address.

### Local development

```bash
cp .env.example .env                       # APP_ENV=local
docker compose up -d db

cd backend
python -m venv venv
SETUPTOOLS_USE_DISTUTILS=stdlib ./venv/Scripts/python -m pip install -r requirements-dev.txt
./venv/Scripts/python -m alembic upgrade head
./venv/Scripts/python ../ai/tools/build_kb.py      # once
./venv/Scripts/python -m uvicorn app.main:app --port 8000

cd ../frontend && npm ci && npm run dev            # http://localhost:5173
```

API docs are at http://127.0.0.1:8000/docs (local only). The backend runs without `--reload`, so restart it after changing Python code, a rule or `.env`.

### Windows setup issues

| Symptom | Fix |
|---|---|
| `SSLError: CERTIFICATE_VERIFY_FAILED` reaching GitHub/HuggingFace | Corporate/AV TLS interception. `pip install pip-system-certs` in the venv |
| `pip install` fails building `hexdump` | Set `SETUPTOOLS_USE_DISTUTILS=stdlib` |
| `ModuleNotFoundError` after a pull | Re-run `pip install -r requirements-dev.txt` |

### Environment variables (repo-root `.env`, annotated in `.env.example`)

| Variable | Default | Purpose |
|---|---|---|
| `APP_ENV` | `local` | Bare-metal runs only (Docker is always `production`). `local` relaxes the startup checks, enables `/docs`, non-Secure cookie |
| `DATABASE_URL` | postgres on 5433 | SQLAlchemy URL (Compose sets it for the container) |
| `POSTGRES_PASSWORD` | — (required by Compose) | Database password; 12+ characters and not an example value outside local |
| `API_BIND` / `UI_BIND` | `127.0.0.1` | Docker port bindings for the API and console; see "Network access" |
| `MAX_CONCURRENT_INGESTS` | 1 | Uploads processed at once; others get 409 |
| `GROQ_API_KEY` | empty | Missing key → explain/chat return 503; the rest works |
| `GROQ_MODEL` | `openai/gpt-oss-120b` | Model override |
| `LLM_TIMEOUT_SECONDS` | 30 | Per-call timeout |
| `RESPONSE_CACHE_ENABLED` / `_TTL_SECONDS` | true / 900 | Explain/chat route cache |
| `ADMIN_USERNAME` | `admin` | Admin account name |
| `ADMIN_PASSWORD_HASH` | empty | bcrypt hash; required outside local |
| `SESSION_SECRET_KEY` | empty | ≥32 chars; required outside local |
| `SESSION_MAX_AGE_SECONDS` | 43200 | Session lifetime |
| `API_KEY` | empty | Optional `X-API-Key` for scripts/CI |
| `LOGIN_RATE_LIMIT_PER_MINUTE` | 5 | Failed-login throttle |
| `RATE_LIMIT_PER_MINUTE` | 300 | General per-IP limit; 0 disables |
| `TRUSTED_PROXIES` | empty | Proxies whose forwarded-for header is trusted |
| `CORS_ALLOW_ORIGINS` | localhost:5173 | Allowed console origins |
| `MAX_UPLOAD_BYTES` | 104857600 | Upload cap |
| `ML_MODE` | `advisory` | `advisory`, `alert` or `off` (ML.md) |
| `DEMO_MODE_ENABLED` | true | Gates `/demo/*` |

The frontend has one build-time variable, `VITE_API_BASE_URL`. No secret is ever baked into the bundle.

---

## 13. Testing

```bash
cd backend
./venv/Scripts/python -m pytest                  # 836 offline tests
./venv/Scripts/python scripts/upload_sweep.py    # every sample file's verdict
./venv/Scripts/python -m pytest -m integration   # 5 tests: real KB/embeddings, Postgres
cd ../frontend && npx tsc -b && npm run lint && npm run build
```

The default run excludes tests marked `integration` and runs against in-memory SQLite. The shared `api_client` fixture wires the real FastAPI app to a fresh database per test. `tests/api/test_auth_routes.py` and the security tests deliberately exercise the real session, CSRF and upload-guard paths instead of overriding them. CI (`.github/workflows`) runs both the backend suite and the frontend checks.

### Manual end-to-end check

1. `docker compose up --build`, then open http://localhost:5173 and sign in.
2. Settings → System status: every component is ready (the LLM shows not ready without a Groq key).
3. Demo Mode → run: an attack capture is ingested, an incident appears, the explanation and a chat answer return.
4. Upload a capture from `backend/sample_logs/real_world_fixtures/detected/` on the Overview or Logs page. Incidents, Alerts, Logs, MITRE and Rules populate.
5. Open the incident and run the AI analysis. Sources, self-critique and the Fact/Inference/Uncertainty breakdown appear.
6. Change the incident status and check the audit trail shows the admin user.
7. Sign out. Every page redirects to `/login`, and the old cookie is rejected by the API.

---

## 14. Measuring detection accuracy

`backend/sample_logs/real_world_fixtures/` holds real, independently sourced EVTX captures:
- **`detected/`** (59) and **`undetected/`** (2): attack captures, split by the current rules' results. The split is an *output* of `build_failure_matrix.py`, which rescans both folders every run.
- **`NightOwl-Benign-Dataset/`** (17 EVTX + `manifest.json`): real workstation and server captures, used as the false-positive corpus and as the ML baseline.

The expected techniques per capture are in `backend/scripts/fixture_ground_truth.json`.

```bash
cd backend
./venv/Scripts/python scripts/run_detection_benchmark.py   # → benchmark_results.md/.json
./venv/Scripts/python scripts/build_failure_matrix.py      # → failure_matrix.md/.json
```

**Current results** (rules and sequence detectors; the ML layer is disabled in both scripts):

| | |
|---|---|
| Attack captures detected with the correct ATT&CK technique | **59/61** |
| Attack captures raising any alert | 60/61 |
| False-positive alerts on 25 benign captures (252,594 events) | **0** |

**Correction (2026-10-08):** `bits_openvpn.evtx` was earlier written off as a mislabelled benign capture. It is malicious: a 32-bit `SysWOW64
otepad.exe` (which never uses BITS) creates BITS jobs with random names that download `https://i.imgur.com/IFpvPlt.png` every few minutes. Classing the whole BITS log as "everyday" briefly made it read Normal. BITS is no longer everyday, and a rule flags BITS jobs created by processes that never use BITS.

The two remaining misses: a UserHunter capture that holds a single `System` -> `\srvsvc` pipe event (identical to an ordinary share browse; it reads **Review recommended**) and the NTLM self-relay capture, which is flagged for its WMI execution and a log clear but whose relay is not visible in those events (the logons are Kerberos).

These are **development-set figures**: every attack capture informed rule development. Each miss in `failure_matrix.md` is classified (`channel_provider_gap`, `rule_missing`, `insufficient_telemetry`, `ambiguous_behavior`, ...) from the real field values.

### The upload sweep: what every sample file shows

`backend/scripts/upload_sweep.py` runs the real engine, detectors, coverage classification and advisory patterns over every EVTX under `sample_logs` and prints the verdict an upload would show. It exits non-zero if a benign file is not **Normal** or an attack file is **Normal**.

| Group | Result |
|---|---|
| 27 benign files (the benign dataset, the real-world benign set, the synthetic noise, `sample.evtx`, `sysmon_demo.evtx`) | **27 Normal** |
| 61 attack captures | 60 Suspicious, 1 Review recommended |

**Caveat:** the "everyday" event lists were derived from, and are checked against, the same benign corpus. A machine that behaves differently can still show Review recommended. Re-run the sweep on any new benign logs; every file that is not Normal is either a new everyday event type to add to `detection/coverage.py` (with its reason) or a real finding.

### Quick API checks

```bash
curl http://127.0.0.1:8000/health
curl -c c.txt -X POST http://127.0.0.1:8000/auth/login -H "Content-Type: application/json" \
     -H "X-NightOwl-Request: 1" -d '{"username":"admin","password":"..."}'
curl -b c.txt "http://127.0.0.1:8000/incidents?limit=2"
curl -b c.txt "http://127.0.0.1:8000/alerts?kind=ml&limit=3"
curl -b c.txt http://127.0.0.1:8000/system/status
curl -b c.txt -H "X-NightOwl-Request: 1" -X POST http://127.0.0.1:8000/incidents/1/explain   # 2 LLM calls
```

A Postman collection is in `docs/postman/`.

---

## 15. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Login always fails in Docker but works locally | Unquoted bcrypt hash in `.env`; Compose expanded its `$` parts | `ADMIN_PASSWORD_HASH='$2b$12$...'` (single quotes) |
| Backend exits at start with a settings error | Outside local mode without a valid `SESSION_SECRET_KEY`/`ADMIN_PASSWORD_HASH`, or with a weak database password | Set them (see §10), or `APP_ENV=local` for a bare-metal development run |
| Upload answers "Another upload is still being processed" (409) | One upload is already running (`MAX_CONCURRENT_INGESTS=1`) | Wait for it to finish; the header shows its progress |
| `docker compose up` complains about `POSTGRES_PASSWORD` | Not set in `.env` | Set it |
| `failed to connect to the docker API` | Docker Desktop is not running | Start it and retry |
| A code change does not show up in the browser, or a large upload is as slow as before | The Docker stack is still running the old images | `docker compose up -d --build` (the database volume is kept) |
| A large upload takes minutes | python-evtx renders about 100-235 records per second per core; files are read in parallel on up to 16 cores (`NIGHTOWL_EVTX_WORKERS` overrides). If worker processes die (for example when Windows runs out of memory), the rest of the file is read in one process instead of being lost. Measured in the Docker backend: 56 MB / 48,125 records in about 95 s end to end | Expected. Use a 5-10 MB capture for a demo. A faster Rust reader exists (`NIGHTOWL_EVTX_BACKEND=rust`) but is experimental and off, because its output is not identical |
| The tab running an upload stops responding after being left in the background | Chrome's Memory Saver suspended or discarded the tab | Keep the tab in front during a long upload; the server finishes the upload either way and stored events are skipped as duplicates on a re-upload |
| First container start is slow | Knowledge-base build downloads the embedding model | Expected once; it's cached in a volume |
| Every POST returns 403 | Client isn't sending `X-NightOwl-Request` | Add the header (the console does) |
| Login returns 429 | Too many failed attempts | Wait a minute |
| Explain returns 503 | No `GROQ_API_KEY`, or the Groq free-tier quota is exhausted | Set a key or wait for the reset |
| ML status "not ready" | Model bundle missing, or trained under a different scikit-learn | `scripts/train_ml_model.py` in the backend venv |
| A rule change has no effect | Rules are cached per process | Restart the backend |
| `tmp_path` tests fail with `WinError 5` | Broken Windows temp ACL | Handled by `tests/conftest.py` (`--basetemp`) |

**Field note:** Sysmon network events (ID 3) could not be captured on the primary dev laptop, because McAfee's WFP firewall blocks Sysmon's network driver. Capture on a clean VM instead.

---

## 16. Frontend data-integrity notes

A KPI and chart audit cross-checked every figure in the console against direct database queries. Bugs it found, all fixed:
- **Old timestamps:** relative times on old fixture data no longer read "47,000 hours ago"; they fall back to absolute dates after 30 days.
- **Time windows:** charts and reports anchor "recent" windows to the dataset's latest timestamp, not `Date.now()`.
- **Labels:** "Detection rate" is renamed "Alerting event rate". Real detection accuracy is in §14.
- **Severity totals:** these come from count queries, not from a client array capped at 1,000.
- **Tactics:** the tactic vocabulary includes `stealth`/`defense-impairment`; the MITRE donut has an "Other" bucket.
- **Sorting:** severity sorts by rank, not alphabetically, and the Incidents sort covers the whole dataset.
- **ML anomalies:** they are kept out of detection counts and alerting-event flags everywhere.

---

## 17. Decision log

**Groq-only LLM.** Gemini's free tier proved unreliable (a 20-request daily quota and overloads). Gemini support was removed rather than kept as a silent fallback.

**pySigma for validation, own evaluator for matching.** No pySigma backend evaluates in-memory events (§5).

**Strict rule loading.** A rule that would silently never match, or that carries a wrong tactic, is worse than a rule that refuses to load.

**Severity = Sigma level + tactic weight.** Only high-leverage tactics add weight, so medium rules stay medium.

**Server-side sessions over a cookie-only session.** Logout has to actually revoke access.

**Demo Mode from the measured corpus.** The fixture list comes from `failure_matrix.json`, so it uses one source of truth and only correctly detected captures.

**A live replay was built, then removed.** Rebasing timestamps onto a wall-clock schedule added a second code path for a "live" feel that a real upload already gives.

**ML rebuilt and demoted to advisory (2026-10).** The first ML version reported 97.8% accuracy measured on its own training data, scored windows shaped unlike real uploads, and alerted on a single logon. It was rebuilt per log family on upload-shaped windows and evaluated honestly. It is still too noisy to assert attacks, so it records evidence and never opens incidents by default. See ML.md.

**ATT&CK index vendored.** The runtime never needs network access, and tests are deterministic.

**Single admin, no RBAC.** NightOwl has one operator.

**Detection decides the technique; the LLM explains (19 Oct 2026).** Retrieval from raw events alone finds the right ATT&CK technique for only 13 of 61 labelled captures in the top 3 (21 with the file name, which leaks the answer). Rules and sequence detectors name the technique; explanation and chat retrieval is filtered to it.

**The LLM gets the event's own fields (19 Oct 2026).** Passing only process, command line and user made 4 of 10 explanations report key facts as missing. Bounded event fields are now part of the evidence.

**Chat requests are size-bounded (19 Oct 2026).** A follow-up on a real capture exceeded the free tier's per-request ceiling; evidence, each earlier turn and the history are now capped.

**Second-opinion technique candidates at 0.55 (19 Oct 2026).** At 0.50 only 23-42% were correct; at 0.55 all were. A wrong technique next to the evidence is worse than none.

**ML stays experimental (19 Oct 2026).** Retraining needs benign logs from at least 5 more machines; the work is deferred, the layer remains advisory and labelled experimental everywhere in the console.

---

## 18. Scope boundaries

Not built, on purpose:
- an evidence graph and multi-host campaign correlation, because no capture in the corpus shows cross-host activity;
- a real-time pipeline (agents, Kafka, websockets): NightOwl analyses uploaded EVTX;
- threat-intel feeds, geo maps and host telemetry (§9);
- multiple users, RBAC, OAuth and password reset.

**Detection accuracy history** (measured each time):

| Stage | Detected |
|---|---|
| First rules | 3/32 |
| Sysmon coverage pass | 18/32 |
| Security-channel pass | 24/32 |
| Corpus grew | 26/39 |
| Sequence detectors added | 33/39 |
| Corpus grew again | 50/61 |
| 2026-10 audit | 52/60 |
| 2026-10-08 upload audit (coverage split, 8 new rules, UserData and RPC parsing) | 59/61, 0 false positives |

The 2026-10 audit changed how detection is scored. A capture now counts only when the alert carries the *correct technique*, and the clean corpus became the 40-capture benign set. Under that scoring the earlier 50/61 was 38/60 with 42 false-positive alerts. Rule fixes and 14 new rules brought it to 52/60 with 5 false positives.

---

## 19. Working conventions

- **Commits:** Conventional Commits (`feat:`, `fix:`, `docs:`, ...), one line, describing the behaviour change.
- **Layering:** routes → services → models.
- **Comments:** they explain why, not what.
- **Tests:** they mirror the package they cover. Every fixed bug gets a regression test.
- **The UI:** nothing reaches it that real data can't back (§9).
- **Free tier only.**
- **Measure before building:** re-run the benchmark and the failure matrix after any detection change, and the ML evaluation after any ML change. Those outputs, not this document, are the source of truth.

---

## 20. Team

A 4-person team working as two rotating pairs across the backend, AI/RAG and frontend tracks, built with AI assistance over a 30-day roadmap.
