# NightOwl — Architecture and Design

How the system is built, why it is built that way, and what it deliberately does not do.
Companion document: [`PROJECT_GUIDE.md`](PROJECT_GUIDE.md) for setup, testing, roadmap and operations.

---

## 1. What the system does

NightOwl turns raw Windows Sysmon/EVTX telemetry into a small number of prioritised, explained incidents.

```
EVTX upload
   |
   v
Ingestion     evtx_reader -> normalizer -> NormalizedEvent   --> events table
   |
   v
Detection     33 Sigma-style YAML rules + a 3-pattern sequence
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
Console       React SOC UI over the REST API
```

Every number the console shows is derived from this pipeline. Nothing is simulated.

---

## 2. Repository layout

```
backend/     FastAPI service - API, detection, ingestion, MITRE mapping,
             services, models, migrations, tests, EVTX sample_logs
frontend/    React 19 + Vite + Tailwind v4 SOC console
ai/          AI layer - RAG corpus, ATT&CK dataset, vector store, build/eval tooling
docs/        This file and PROJECT_GUIDE.md
```

The RAG *runtime code* lives in `backend/app/rag/` because the API service imports it directly (`app.rag.explain_service`); `ai/` holds the corpus, the vector store and the tooling that builds them. Splitting the code into a separately installed package would buy indirection rather than clarity at this size.

**Backend layering rule:** routes -> services -> models/db. Only the service layer talks to the database; routes compose services and own their Pydantic response models (file-local, no shared `schemas/` layer).

---

## 3. Data model

PostgreSQL 16 (host port 5433), SQLAlchemy 2 declarative models, Alembic migrations.

| Table | Key fields |
|---|---|
| `events` | `id`, `host`, `timestamp`, `event_id`, `process`, `command_line`, `user`, `raw_json` |
| `alerts` | `id`, `event_id` to events, `rule_id` (Sigma UUID), `matched_at`, `severity`, `incident_id` |
| `incidents` | `id`, `title`, `status`, `severity`, `host`, `mitre_technique_ids` (JSON list), `created_at` |
| `chat_messages` | `id`, `incident_id`, `role`, `content`, `created_at` |
| `audit_log` | `id`, `entity_type`, `entity_id`, `action`, `actor`, `details`, `created_at` |
| `rules` | Defined but unused - detection rules live as YAML files, not rows |

`raw_json` stores both the original record and the normalized view, so fields the normalizer does not promote to columns (ParentImage, Hashes, the network 5-tuple) are never lost.

**Severity vocabulary**, shared verbatim by the backend, the API and the UI: `informational | low | medium | high | critical`.

---

## 4. API surface

No prefix; all routes are mounted at root and (except `/health`) sit behind `require_api_key`.

| Method | Path | Notes |
|---|---|---|
| GET | `/health` | Liveness only. Exempt from rate limiting. |
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
| POST | `/demo/reset` | Deletes every event/alert/incident/chat/audit row, so Demo Mode can re-ingest its bundled fixtures from a clean slate |

The `/demo/reset` route sits behind an additional `require_demo_mode` gate (`DEMO_MODE_ENABLED`, on by default) on top of the usual API key, since it is destructive.

Error shape is uniform: `{"detail": "<string>"}`. `LLMProviderError` gives 503; anything unhandled gives 500; throttled gives 429.

**No sorting parameters and no aggregate/stats endpoints** - list endpoints are hardcoded newest-first, and every dashboard figure is computed client-side from the pages the console already fetched.

**No websocket or SSE.** Live data in the console is polling, deliberately: building a streaming transport purely so the UI could feel live would be backend scope with no other consumer.

---

## 5. Detection engine

Rules are Sigma-style YAML files in `backend/app/detection/rules/` (33 of them as of 2026-09-05, up from the original 15 -- see `backend/scripts/failure_matrix.md` and repo-root `pending.md` for the real-world-fixture-driven trail of what each later addition closed and why), loaded once at first use and cached in-process.

- **pySigma is used for validation only.** Its design centres on backends that convert a rule into a target query language (Elasticsearch DSL, Splunk SPL) to run against an external log store; there is no official backend for evaluating a rule against a single in-memory dict, which is exactly what `POST /ingest` needs. So `SigmaRule.from_yaml()` validates structure (real errors, not decoration) and a small hand-rolled interpreter in `engine.py` evaluates the `detection` block parsed separately with `yaml.safe_load`.
- **Supported subset:** named selections (AND across fields, OR across a value list), contains/startswith/endswith/exact modifiers, all case-insensitive, and a boolean condition string (and/or/not/parentheses) via a recursive-descent parser, not `eval()`, since rule files are treated as untrusted input.
- **Not supported (by design, v1):** regex and glob modifiers, "1 of"/"all of" shorthand, named multi-condition rules.
- **Rules match real Sysmon field names** (Image, CommandLine, DestinationIp) rather than an invented vocabulary, so they stay portable from public SigmaHQ sources. `NormalizedEvent.event_data` carries the full flattened EventData dict, so the engine sees every field without re-parsing XML.
- **Category to Sysmon event id:** process_creation=1, network_connection=3, file_event=11, registry_event=13 (Value Set only, the event that carries TargetObject/Details).

**Severity scoring** (`services/severity_service.py`): base Sigma level rank (1-5) plus the highest MITRE tactic weight among the rule's own tags: 0 for reconnaissance and resource-development, +1 for initial-access, execution, persistence, privilege-escalation and defense-evasion, +2 for credential-access, discovery, lateral-movement and collection, +3 for command-and-control, exfiltration and impact; capped at critical. So a medium rule tagged command_and_control outranks a medium rule tagged reconnaissance.

**Incident grouping** (`services/incident_service.py`): a match joins the most recent open incident for the same host within a 1-hour window, merging its technique id and raising severity to the higher of the two; otherwise a new incident is created.

**The 33 rules** cover execution (T1059.001 encoded PowerShell and execution-policy bypass, T1218 pcalua LOLBin, T1218.005 mshta, T1105 certutil download / ftp.exe child process / suspicious writes to public-or-temp), persistence (T1547.001 Run keys, T1546.012 IFEO debugger, T1053.005 scheduled tasks via schtasks and PowerShell, T1546.008 accessibility-tool/sticky-keys hijack, T1546.003 WMI CommandLineEventConsumer), privilege escalation and defense evasion (T1548.002 UAC bypass via sdclt.exe and UAC disabled via registry, T1134.001 rogue spoolss named pipe/SeImpersonate, T1070.006 timestomping, T1014 known-abusable/BYOVD driver load, T1685.005 security audit log cleared), credential access (T1003.001 LSASS memory dump via process access *and* via Security-channel object-access auditing, T1003.002 SAM/SYSTEM/SECURITY hive dump, T1003.006 DCSync), discovery (T1069.001 sensitive local group/account enumeration via net.exe), lateral movement (T1021.001 RDP, T1021.002 admin share, T1021.006 WinRM network connection and process spawned by a WinRM host, T1570 admin-share executable payload write, T1572 RDP logon over a loopback tunnel) and command and control (T1071.001 LOLBin network connection). T1055 (Remote Thread Creation from a scripting engine or web-server process) sits across the defense-evasion/privilege-escalation boundary, matching Process Injection's own real ATT&CK family.

**Two mechanisms sit outside this single-event Sigma engine entirely, both narrow and built only once real fixture data justified them (never speculatively):**

- **The sequence engine** (`detection/sequences.py`) hand-codes 3 multi-event correlations no single-event rule can express -- "did event A, then B, then C happen together" or "did N distinct things happen from one source within a window." Process Herpaderping (FileCreate -> ProcessAccess -> ImageLoad, chained via Sysmon `ProcessGuid`, T1055), an SMB share-enumeration probe (a `\srvsvc` PipeConnect corroborated by an inbound port-445 connection, T1135), and a Kerberos password spray (>=4 distinct `TargetUserName` values from one source IP within 60s, T1110.003). It runs once per ingest batch after the per-event rule loop, feeding the same `find_or_create_incident`/`save_alerts` path a normal rule match uses -- there is no parallel Alert/Incident creation logic, just a second source of `RuleMatch`es. Its `rule_id`s are never loaded YAML, so any route resolving an alert's title/technique (`routes_alerts.py`, `routes_events.py`, `routes_incidents.py`) merges in `SEQUENCE_PATTERNS` alongside `get_loaded_rules()`.
- **Advisory patterns** (`services/advisory_patterns.py`) are narrow event shapes too false-positive-prone for a deterministic rule (e.g. `\lsass`/`\srvsvc` named-pipe connects from `System`) but still worth a human second look -- routed to the LLM advisory second-opinion mechanism (`ai_opinion_service.py`) instead, never creating an Alert/Incident/severity score of their own.

---

## 6. MITRE ATT&CK mapping

- Official STIX bundle (ATT&CK v19.2), downloaded on first use and cached at `ai/mitre/enterprise-attack.json`.
- Per technique: id, name, description, tactics, is_deprecated, is_revoked. Nothing else: no platforms, data sources or detection guidance.
- **Two tactic vocabularies exist and must be normalised when joined.** The ATT&CK dataset returns hyphenated kill-chain phase names (defense-evasion), while this project's rule tags use underscores (defense_evasion). The frontend keeps the hyphenated list in `lib/tactics.ts`; `severity_service` keys on underscores. An earlier bug silently broke every multi-word tactic by mixing the two.
- **Invalid technique tags are warn-only, never rule-rejecting.** A bad tag is a metadata problem; the rule's detection logic still works and should keep firing. Dropping the rule would lose real coverage over a documentation issue.

---

## 7. AI layer

### Corpus and retrieval

`ai/tools/build_kb.py` chunks MITRE technique descriptions (skipping deprecated and revoked techniques) plus the hand-written playbooks in `ai/knowledge_base/playbooks/`, embeds them with sentence-transformers all-MiniLM-L6-v2, and writes a single knowledge_base collection into `ai/vector_store/` (currently around 1,900 chunks). Chunks are 800 characters with 100 characters of overlap, split on paragraph and sentence boundaries.

Retrieval is top-k (k=5) with an optional technique-id filter. The embedding model is the project's own wrapper, not Chroma's implicit default, so query vectors and stored vectors always come from the same model.

### Generation

`rag/explain_service.py` runs **retrieve, draft, self-critique**: one LLM call produces the explanation from the incident context plus retrieved chunks, and a second call checks that draft against both the chunks and the incident context. Flagged claims are appended to the response as a confidence-check block rather than silently removed, so the analyst sees what the model itself was unsure about.

Chat (`rag/chat_service.py`) is a single call per turn, with no critique pass. Chat is a back-and-forth where the user can immediately challenge a wrong answer, and a second call would double the free-tier cost of every turn.

Prompts live together in `rag/prompts.py` (build_explanation_prompt, build_critique_prompt, build_chat_prompt). All three spell out the difference between general technique background and incident-specific fact, which is the fix for a real hallucination pattern described below.

### Providers, timeouts, caching

- `LLM_PROVIDER` selects gemini or groq; the call is fully abstracted behind `rag/llm_client.py`, so swapping providers touches one file.
- Provider kwarg names differ and were verified against the installed packages: ChatGoogleGenerativeAI takes `timeout`, ChatGroq takes `request_timeout`. Passing the wrong one fails silently.
- Two distinct caches. `rag/cache.py` is on by default, keyed on incident id (plus message for chat), TTL 900s, and sits at the route layer so a hit skips retrieval too. `llm_client._response_cache` is off by default and keyed on the rendered prompt hash, for repeated manual testing without spending quota.
- One retry with a 2s delay; LLMProviderError surfaces as a 503 carrying the provider's own message rather than a generic 500.

### What the model can and cannot see

**Fixed 2026-09-05 -- this used to be a real, documented gap.** Earlier, the LLM received only the incident's title, severity, host and technique ids, not the underlying command lines, processes or users -- explanations were about the technique in the abstract, not the actual evidence on that machine. `services/incident_service.py::build_incident_evidence()` now pulls the incident's first alert's real process, parent process, command line, user, matched rule title, detection method (Sigma rule vs. sequence correlation), and up to 5 nearby related events -- the same per-alert evidence `GET /incidents/{id}` already assembles -- into both the explain and chat prompts. Bounded to one alert's detail (not every alert an incident has) so a rule that fired dozens of times doesn't balloon the prompt; the rest are counted, not individually listed. Verified live: asked the chat "what process or parent process triggered this alert?" and it answered from the real (absent, in that case) evidence instead of guessing.

### Evaluation results

**Retrieval quality** (10 queries against the real knowledge base): 9 of 10 returned the correct playbook or technique document in the top 3. The one failure was that beaconing-phrased queries under-retrieved the C2 playbook because the playbook text never uses the word "beaconing" - a corpus vocabulary gap rather than a retriever bug.

**Hallucination spot-check** (10 crafted incidents): three findings, two fixed.
1. Self-critique flagged the incident's own host field as unsupported on every run, because the critique prompt only ever saw the draft and the chunks, never the incident context those chunks are checked against. Fixed: incident context is now passed into the critique, and first-party fields are declared known-true.
2. A draft asserted an `-enc` flag as something this incident showed when the event never had it; the model had imported the detail from the only available T1059.001 playbook. Fixed: both the generation and critique prompts now require that any stated technical detail be literally present in the incident context to count as observed.
3. Hallucination density tracked knowledge-base coverage: incidents whose technique had no playbook drew more unsupported detail. The fix is corpus work (more playbooks), not prompt work, and it remains the highest-leverage follow-up.

**Cost and latency** (Groq openai/gpt-oss-120b, 5 incidents x 2 calls): roughly 4-8 seconds and 2,000-3,000 total tokens per explanation across the draft and critique pair. Each `/explain` therefore costs *two* provider requests, which is what makes a 20-requests/day free tier tight and why the response cache is on by default.

---

## 8. Frontend

React 19 + Vite + TypeScript + Tailwind v4 (CSS-first `@theme`), react-router 7, Recharts, Motion, lucide-react. Linted with oxlint.

### Structure

```
src/
  api/          One fetch client mirroring every backend response model
  components/   ui/ design system + feature folders (dashboard, incidents,
                chat, logs, rules, search, notifications, brand)
  context/      Preferences, health, incidents snapshot, MITRE catalog, toasts
  hooks/        One data hook per screen concern
  lib/          Tokens, aggregations, filtering, formatting, navigation, polling
  layout/       Sidebar, Topbar, AppLayout shell
  pages/        One file per route
```

### Design system

All colour, type, spacing, radius, shadow and glow values are CSS custom properties in `src/index.css`, mirrored for chart libraries in `src/lib/tokens.ts` (Recharts and inline SVG cannot read CSS variables). No component contains a raw hex value.

Tailwind's JIT only sees complete class names in source, so every colour-varying utility is a literal string in a lookup map (`components/ui/accent.ts`, `lib/severity.ts`). Building a class with a template literal produces no CSS at all - this is the single most important rule when editing the UI.

### Pages

Overview, Incidents, Incident detail, AI Assistant, MITRE ATT&CK, Alerts, Logs, Rules Engine, Reports, Settings, Demo Mode. Global command palette (Ctrl/Cmd+K) searches incidents, techniques, rules, events and navigation; the notification bell surfaces unacknowledged open incidents.

### Data flow and request budget

The incidents snapshot and MITRE catalog are fetched once into context and shared; everything else is per-screen hooks. Because the API has no aggregate endpoints, all dashboard figures are computed in `lib/aggregations.ts` from those cached pages.

Three background pollers exist (health, live log stream, incident snapshot). They pause when the tab is hidden and back off exponentially when throttled, and the API client de-duplicates in-flight GETs so simultaneous consumers of the same endpoint cost one request. A dashboard paint is about ten requests; before that de-duplication it was twelve, and up to twenty-four in development where React StrictMode double-invokes effects. This mattered because the backend rate limiter is a token bucket: exceeding it left the console retrying into an empty bucket.

---

## 9. Honesty policy

The design references this console was built against included panels that a system like this cannot truthfully populate. Rather than fabricate them, each was replaced by something the data supports:

| Reference panel | What NightOwl shows | Why |
|---|---|---|
| World threat map with attack arcs | Host activity graph (hosts linked by shared techniques) | The system ingests local Windows event logs and holds no geolocation data whatsoever |
| System health: CPU / memory / disk / network | Pipeline health: API latency, rules loaded, events ingested, detection rate | There is no host-telemetry collection and no metrics endpoint; `/health` is a liveness probe |
| Assets monitored | Hosts affected (distinct hosts with an incident) | There is no asset inventory, only hosts that have sent telemetry |
| Percentage change "from yesterday" | Real 24h-over-24h delta, or an explicit "not enough history to compare" | Computed from ingested timestamps; shown only when a comparable previous window exists |
| Signed-in user with avatar, email and role | Local deployment identity | There are no accounts, sessions or roles; auth is one optional shared API key |
| Alert status workflow | Parent incident status | Alerts have no independent status; the incident is where status lives |
| Log storage and retention | Ingest summary (events stored, alerting, hosts, time span) | Events are stored in Postgres with no retention policy to report |
| Enable/disable rule toggles | Read-only enabled state with an explanation | Rules are version-controlled files; no endpoint edits them at runtime |
| Threat intelligence feed | Not present at all | No feed is integrated, and a placeholder page is a promise the product does not keep |
| "Live" incident feed for a demo | Demo Mode (section 10): a real fixture pushed through the genuine `POST /ingest` -> explain -> chat pipeline | Nothing is generated or scripted-in-time; every record, rule match and AI reply is a real backend response to a real upload |

Confidence figures follow the same rule: the UI shows retrieval similarity scores and the model's own self-critique result, never an invented confidence percentage.

---

## 10. Demo Mode

Demo Mode is a one-shot, client-driven walkthrough, not a server-side simulation: `frontend/src/hooks/useDemoMode.ts` fetches one bundled fixture from `frontend/public/demo/`, wraps it in a real `File`, and drives it through the exact same sequence a person would trigger by hand -- `POST /ingest`, then `POST /incidents/{id}/explain`, then `POST /incidents/{id}/chat` with one scripted question. Every stage awaits a real backend round trip; nothing is mocked or pre-recorded, and the narration log only advances alongside an actual response.

**No rebased or simulated time.** Earlier revisions of this project explored a server-side "live replay" that rewrote real captures' timestamps onto a compressed wall-clock schedule so a demo could look like a live shift. It was removed (see the decision log) in favour of this simpler model: a fixture is ingested once, at real ingest time, and the resulting incident is exactly what `POST /ingest` on that file would produce for any user.

**Reset is total, not scoped.** `POST /demo/reset` (`app/api/routes_demo.py`) deletes every row from all operational tables so the bundled fixtures can be re-ingested from a clean slate. Nothing distinguishes a demo-ingested row from a manually uploaded one, by design -- Demo Mode has no privileged data path.

---

## 11. Decision log

One entry per significant decision. Every one names its alternative and whether it is reversible.

**LLM provider: free-tier Gemini via langchain-google-genai, with Groq as an alternate (2026-08-16).** Paid APIs were ruled out by project policy. Gemini needs no billing setup and plugs straight into the prompt templates; the model alias `gemini-flash-latest` avoids a forced migration when Google retires a pinned snapshot. Groq was added later as an alternate provider after the Gemini daily cap proved tight. Reversible: the call is abstracted behind one file.

**pySigma for validation, own evaluator for matching (2026-08-16).** See section 5. Reversible: only rule_loader and engine know about it.

**Rules match raw Sysmon field names, not the normalized schema (2026-08-16).** Portability from public Sigma sources beats an invented vocabulary, and carrying the full EventData dict on NormalizedEvent avoids coupling the engine to XML parsing. Reversible: event_data is additive.

**Alert severity is a pass-through of the rule's computed level (2026-08-18).** A translation table would have mapped each string to itself. Note the meaning changed at Day 10: the level passed through is now the tactic-weighted value, not the raw Sigma level.

**Registry detection scoped to Sysmon event 13 (2026-08-19).** Value Set is the event carrying the fields both target rules need; supporting 12/14 would require a category-to-many-event-ids mapping. Reversible and additive.

**Scheduled-task rules are process_creation rules (2026-08-19).** Sigma's scheduled-task category is backed by Security log 4698, which this project does not ingest. Detecting schtasks.exe and the PowerShell cmdlets as process creation is both standard practice and needs no engine change.

**Severity combines Sigma level with MITRE tactic weight (2026-08-19).** Both are read from the rule's own tags. Rules with no tactic tag contribute zero weight, so no earlier rule or test changed behaviour.

**Tests mirror the app package structure (2026-08-19).** Twenty-four flat `test_dayN_*.py` files became subpackages matching `app/`, with shared TestClient boilerplate extracted into a conftest fixture. One roadmap-named file was deliberately renamed for consistency. Coverage was verified unchanged at every step rather than only at the end.

**Invalid MITRE tags are warn-only (2026-08-18).** See section 6.

**Structured logging is a 30-line stdlib JSON formatter (2026-08-19).** structlog and python-json-logger were the alternatives; the requirement was structured logs, not an observability stack, and the project avoids dependencies it can write in a few lines. Later hardened: the formatter escapes non-ASCII and the handler forces UTF-8, because a legacy Windows console encoding turned a model response containing a typographic dash into a 500.

**One shared JSON 500 handler instead of per-route try/except (2026-08-19).** The real gap was Starlette's plain-text fallback for uncaught exceptions breaking the JSON contract exactly when it matters most.

**Chat splits RAG orchestration from persistence (2026-08-19),** mirroring the explain endpoint: `rag/chat_service.py` orchestrates, `services/chat_service.py` persists, the route composes both.

**Self-critique also sees the incident context (2026-08-19).** Driven by two measured hallucination findings; see section 7.

**LLM robustness: explicit timeout, dedicated 503, opt-in prompt cache (2026-08-19).** Before this a hung provider call could block indefinitely and a provider failure was indistinguishable from a bug.

**Token/latency measurement is a separate function (2026-08-19).** `generate_with_metrics()` sits alongside `generate()` rather than changing its contract, and deliberately bypasses the cache so it measures a real call.

**Two response caches, and a fixed "system" audit actor (2026-08-21).** The route-level cache is on by default and keyed on incident id; the prompt-hash cache is a testing aid. The audit actor is fixed because no per-user identity exists anywhere in the system.

**A broken Windows temp-directory ACL is worked around in conftest, not at the OS level (2026-08-19).** pytest's tmp_path fixture failed at setup for every test using it; the fix redirects basetemp when it detects that specific failure, and is a no-op on healthy machines.

**Rate limiting is a per-IP token bucket, with /health exempt and a 300/min ceiling (2026-08-27).** The original 60/min was one token per second, while a single dashboard paint legitimately costs about a dozen requests, so ordinary use throttled itself. Exempting the liveness probe stops a busy API from being reported as a dead one.

**Reports and settings are client-side by design (2026-08-27).** There is no reports table and no settings endpoint, so the Reports page generates its document live from API data and exports it locally, and Settings stores genuinely local browser preferences. Neither pretends to persist server-side.

**Live SOC replay was built, then removed in favour of one-shot Demo Mode (built 2026-08-28, removed 2026-09).** The original replay rewrote real captures onto a compressed wall-clock schedule via a background `threading.Thread`, so detections appeared to surface over simulated time. It worked, but it was a second, parallel demo code path (`app/demo/`, `services/replay_service.py`, `services/demo_service.py`) carrying its own test suite and its own class of bug (see the reset/grouping-window note this decision log used to carry) for a benefit -- a "live" feel -- that a straightforward real upload through `POST /ingest` already delivers honestly. It was cut once effort shifted toward real-world detection coverage (see the failure-matrix work referenced in `pending.md`), where that maintenance surface wasn't paying for itself. Demo Mode (section 10) keeps the same non-negotiable -- no fabricated or client-suppliable telemetry -- with less machinery. Reversible: the deleted modules are recoverable from git history, and nothing else in the ingest path depended on them (`services/ingest_service.py`'s shared `ingest_records()` is unaffected).
