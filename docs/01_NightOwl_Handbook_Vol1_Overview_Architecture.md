# NightOwl — AI-Powered Security Operations Center
## Engineering Handbook — Volume 1: Overview, AI Collaboration Rules, Architecture, SDLC

**Project type:** Final Year Major Project (Team of 4, AI-assisted)
**Duration:** 30 days
**Status:** Pre-development / Planning baseline (Day 0)
**Team structure:** Two rotating pairs (Pair 1 + Pair 2, 2 members each) — see Volume 2 for the day-by-day pair assignments and rotation schedule.

This document is the permanent context file. Paste it (or its relevant section) into any AI assistant — Claude, ChatGPT, Gemini, Cursor, Codex, Windsurf — before asking it to write code, so it understands the project the same way every time.

---

## SECTION 1 — PROJECT OVERVIEW

### 1.1 Vision
A junior security analyst should be able to open NightOwl, see a raw stream of Windows Sysmon events transformed into a small number of prioritized, explained incidents, and know what to do next — without needing 5 years of SOC experience to interpret raw logs.

### 1.2 Mission
Take unstructured endpoint telemetry (Sysmon/EVTX), apply detection logic (Sigma rules mapped to MITRE ATT&CK), enrich the resulting alerts with threat intelligence context, and use a Retrieval-Augmented Generation (RAG) LLM agent to turn "Event ID 1, CommandLine=powershell -enc ..." into "This looks like an obfuscated PowerShell execution technique (T1059.001), commonly used for initial payload delivery. Recommended response: isolate host, capture memory, check parent process chain."

### 1.3 Problem Statement
- Real SOCs are flooded with alerts ("alert fatigue"). Analysts need context, not more raw data.
- Junior analysts don't intuitively map a raw log line to a MITRE technique.
- Most student cybersecurity projects either (a) build a toy log viewer with no real detection logic, or (b) build a detection engine with no usable interface. NightOwl's differentiator is combining real detection engineering (Sigma + MITRE mapping) with an LLM reasoning layer, in a working full-stack product.

### 1.4 Why This Project Exists
It demonstrates, in one project, competency across: backend engineering (FastAPI), data engineering (log parsing/normalization), applied ML/LLM engineering (RAG, embeddings, agents), cybersecurity fundamentals (Sysmon, ATT&CK, Sigma), and product thinking (a dashboard a human can actually use). That breadth is exactly what a final-year capstone should prove.

### 1.5 Expected Outcome
A working, Dockerized, demoable Proof of Concept where:
1. Sample Sysmon/EVTX logs are ingested and normalized.
2. Sigma-rule-based detection logic flags suspicious events.
3. Flagged events are mapped to MITRE ATT&CK techniques.
4. A RAG pipeline (ChromaDB + LangChain + LLM) retrieves relevant context (technique descriptions, past incidents, response playbooks) and generates a plain-English explanation and recommended response.
5. A React dashboard displays incidents, timelines, MITRE heatmap, and an "ask the incident" chat interface.

### 1.6 Success Criteria
- [ ] Can ingest a real/sample EVTX or Sysmon log file end-to-end without manual intervention.
- [ ] At least 15–20 Sigma-style detection rules implemented and demonstrably firing on test data.
- [ ] Each alert maps to a MITRE ATT&CK technique ID with a confidence/severity score.
- [ ] LLM agent produces a coherent, grounded (RAG-sourced, not hallucinated) explanation for at least 90% of test incidents.
- [ ] Dashboard shows a live/near-live incident feed, MITRE ATT&CK heatmap, and incident detail view with chat.
- [ ] Entire stack runs via `docker compose up`.
- [ ] Documented, defensible in a viva/demo: you can explain every design decision.

### 1.7 Scope (v1 — what you WILL build)
- Log ingestion: Sysmon EVTX file upload + parsing (batch, not live agent-based collection).
- Detection: Rule-based (Sigma-style YAML rules evaluated against normalized events).
- Enrichment: MITRE ATT&CK technique mapping; optional static threat-intel lookups (e.g., known-bad hash/IP lists you bundle, not live API dependence).
- AI layer: RAG over a knowledge base of MITRE technique docs + your own playbooks, using one LLM provider.
- Frontend: Dashboard with incident list, detail view, MITRE heatmap, chat-with-incident.
- Deployment: Docker Compose, local/VM demo.

### 1.8 Out of Scope for v1 (explicitly deferred)
- Real-time/streaming log collection agents (Winlogbeat/Elastic Agent style).
- Multi-tenant / multi-organization support.
- Live external threat-intel API integrations (VirusTotal, AbuseIPDB) — optional stretch, not core.
- Automated response/SOAR actions (isolating hosts, killing processes) — recommend only, never execute.
- Custom ML anomaly-detection models (v1 is rule-based detection + LLM reasoning, not ML-based detection).

### 1.9 Future Scope (v2+, mention in report as "future work")
- Live agent-based ingestion, streaming architecture (Kafka).
- ML-based anomaly detection layered on top of Sigma rules.
- Multi-user roles (analyst/admin), audit logging.
- Real threat-intel API integrations.
- SOAR-style guarded auto-response actions.

---

## SECTION 2 — HOW THE AI ASSISTANT SHOULD HELP

### 2.1 Your role (AI assistant reading this)
You are acting as a **pairing senior engineer and mentor**, not an autocomplete tool. The team is a group of 4 students who are learning while building. Your job is to make sure they understand *why*, not just *what* — and to be clear about which pair/member a given task or explanation is for when it matters.

### 2.2 Hard rules — the AI must NOT:
- Skip explanations of *why* a design or code choice was made.
- Generate large, unreviewed blocks of code the developer didn't ask for.
- Over-engineer (no premature microservices, no unnecessary abstraction layers, no adding Kubernetes/Kafka/etc. to a 4-person, 30-day student project).
- Add features not on the roadmap without flagging it as an explicit, opt-in scope change.
- Change an established architectural decision silently — always explain the tradeoff and get confirmation first.

### 2.3 The AI must ALWAYS explain, for any non-trivial suggestion:
- **Why** this approach, in plain language.
- **How** it works, step by step.
- **Tradeoffs** versus at least one alternative.
- **Best practice / industry standard** it aligns with, if any.

### 2.4 Default code generation behavior
- Prefer small, single-responsibility files/functions over one giant file.
- Ask "does this fit today's roadmap task?" before adding scope.
- When unsure of intent, ask a clarifying question rather than guessing large amounts of code.

---

## SECTION 3 — PROJECT ARCHITECTURE

### 3.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          NightOwl SOC Platform                       │
│                                                                       │
│  ┌────────────┐      ┌──────────────┐      ┌────────────────────┐   │
│  │  Sysmon /  │      │   Ingestion   │      │   Normalization     │   │
│  │ EVTX Logs  │─────▶│   Service     │─────▶│   (common schema)   │   │
│  │ (files)    │      │  (FastAPI)    │      │                     │   │
│  └────────────┘      └──────────────┘      └──────────┬──────────┘   │
│                                                          │              │
│                                                          ▼              │
│                                          ┌───────────────────────────┐│
│                                          │   Detection Engine         ││
│                                          │  (Sigma rule evaluation)   ││
│                                          └──────────────┬────────────┘│
│                                                          │              │
│                                                          ▼              │
│                                     ┌────────────────────────────────┐│
│                                     │  MITRE ATT&CK Mapping +         ││
│                                     │  Severity Scoring                ││
│                                     └───────────────┬────────────────┘│
│                                                       │                 │
│                          ┌────────────────────────────┼──────────────┐ │
│                          ▼                            ▼              │ │
│              ┌───────────────────┐        ┌───────────────────────┐ │ │
│              │  PostgreSQL        │        │   RAG Pipeline          │ │ │
│              │  (events, alerts,  │◀──────▶│  (LangChain + Chroma   │ │ │
│              │   incidents)       │        │   + LLM API)           │ │ │
│              └─────────┬──────────┘        └───────────┬───────────┘ │ │
│                        │                                 │             │ │
│                        └────────────────┬────────────────┘             │ │
│                                          ▼                              │ │
│                              ┌───────────────────────┐                  │ │
│                              │   FastAPI REST API      │                  │ │
│                              └───────────┬─────────────┘                  │ │
│                                          ▼                                 │ │
│                              ┌───────────────────────┐                     │ │
│                              │  React + Vite +         │                     │ │
│                              │  Tailwind Dashboard     │                     │ │
│                              └───────────────────────┘                     │ │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.2 Data Flow (step by step)
1. Analyst uploads a Sysmon EVTX file (or sample dataset) via dashboard or API.
2. Ingestion service parses EVTX → structured JSON events.
3. Normalization layer maps vendor-specific fields into NightOwl's common event schema (timestamp, host, user, process, command_line, event_id, etc.).
4. Detection engine runs each normalized event (and relevant event sequences) against the loaded Sigma-style rule set.
5. Matches become **alerts**; alerts are grouped into **incidents** (one incident may aggregate several related alerts).
6. Each incident is mapped to one or more MITRE ATT&CK techniques and given a severity score.
7. On demand (or automatically for high severity), the RAG pipeline retrieves relevant MITRE technique docs + playbook snippets from ChromaDB and asks the LLM to generate a human-readable explanation + recommended response.
8. Everything is persisted in PostgreSQL; the dashboard reads via the FastAPI REST API and lets the analyst chat with a given incident (RAG-grounded Q&A).

### 3.3 Folder Structure (proposed baseline — confirm before Day 1 coding)

```
nightowl/
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── core/                # config, settings, logging
│   │   ├── api/                 # FastAPI routers (v1)
│   │   │   ├── routes_events.py
│   │   │   ├── routes_incidents.py
│   │   │   ├── routes_chat.py
│   │   │   └── routes_ingest.py
│   │   ├── ingestion/           # EVTX parsing, normalization
│   │   ├── detection/           # Sigma rule engine
│   │   │   └── rules/           # .yml Sigma-style rules
│   │   ├── mitre/               # ATT&CK mapping data + logic
│   │   ├── rag/                 # LangChain pipeline, embeddings, retrieval
│   │   ├── models/               # SQLAlchemy models
│   │   ├── schemas/              # Pydantic schemas
│   │   ├── services/             # business logic layer
│   │   └── db/                   # session, migrations (Alembic)
│   ├── tests/
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── hooks/
│   │   ├── api/                  # API client
│   │   └── App.tsx
│   ├── package.json
│   └── Dockerfile
├── data/
│   ├── sample_logs/               # sample EVTX/Sysmon test data
│   └── knowledge_base/            # MITRE docs, playbooks for RAG ingestion
├── docs/                          # this handbook + generated docs
├── docker-compose.yml
└── README.md
```

### 3.4 Backend Architecture
Layered, not "fat routers": `api/` (HTTP layer only) → `services/` (business logic) → `models/`+`db/` (persistence). Detection and RAG are treated as internal services called from `services/`, not from routers directly. This keeps routers thin and testable, and keeps detection/RAG logic reusable (e.g., callable from a CLI script for batch testing) without going through HTTP.

### 3.5 Frontend Architecture
Standard React + Vite SPA. `pages/` = route-level screens (Dashboard, Incident Detail, Rules Manager, Settings). `components/` = reusable presentational pieces (AlertCard, SeverityBadge, MitreHeatmap, ChatPanel). `api/` = a thin fetch/axios wrapper so components never call `fetch` directly — keeps API contract changes localized to one file.

### 3.6 Database Architecture (initial schema sketch — refine in Phase 2)
- `events` — raw normalized events (host, timestamp, event_id, process, command_line, user, raw_json)
- `alerts` — detection matches (event_id FK, rule_id, matched_at, severity)
- `incidents` — grouped alerts (title, status, severity, mitre_technique_ids[], created_at)
- `rules` — Sigma rule metadata (id, name, mitre_technique_id, yaml_path, enabled)
- `chat_messages` — incident chat history (incident_id FK, role, content, created_at)

### 3.7 AI Pipeline (RAG)
1. **Knowledge base build (offline/setup step):** Chunk MITRE ATT&CK technique descriptions + your written response playbooks → embed with Sentence Transformers → store in ChromaDB.
2. **Retrieval:** Given an incident (its matched technique ID + raw event context), retrieve top-k relevant chunks from ChromaDB.
3. **Generation:** LangChain assembles a prompt (incident data + retrieved chunks) → sends to the chosen LLM provider → returns explanation + recommended response.
4. **Chat:** Follow-up questions reuse the same retrieval step, scoped to that incident's context, so the LLM stays grounded rather than hallucinating.

### 3.8 Cybersecurity Pipeline
Sysmon EVTX → python-evtx/Evtx parsing → field normalization → Sigma rule matching (using a Sigma rule interpreter, e.g. `pySigma`) → MITRE ATT&CK technique tagging (via the official MITRE ATT&CK STIX/JSON dataset) → severity scoring heuristic (rule severity + technique tactic weight + frequency).

### 3.9 Deployment Architecture
`docker-compose.yml` with services: `backend` (FastAPI), `frontend` (Vite build served via nginx or Vite preview), `db` (PostgreSQL), and ChromaDB either embedded (local persistence directory) or as its own service depending on chosen ChromaDB mode. Single `.env` for secrets (LLM API key, DB credentials) — never committed to Git.

---

## SECTION 4 — COMPLETE SDLC PLAN

This is a 30-day, 4-person team plan. Two pairs (**Pair 1**, **Pair 2**) work in parallel through most phases rather than one person moving through phases sequentially — see Volume 2 for the exact day-by-day, per-pair task breakdown and the rotation schedule (each pair touches backend, AI/RAG, and frontend at some point).

### Phase 0 — Research, Planning & Design (Days 1–4, whole team, split by pair)
**Objectives:** Understand Sysmon/EVTX format, MITRE ATT&CK structure, Sigma rule syntax, and RAG fundamentals; finalize architecture, folder structure, DB schema v1, API contract v1, LLM provider choice, rule template, KB source list, and dashboard wireframes.
**Deliverables:** Research notes, finalized architecture diagram, ERD, API spec draft, rule YAML template + 3 example rules, 4 wireframe screens, KB source list + 2 draft playbooks, working test LLM API call.
**Completion criteria:** Everyone on the team can explain what an EVTX Event ID 1 vs 3 vs 11 means and what a Sigma rule looks like; the plan could be handed to a developer outside the team and they'd understand what to build.
**Common mistakes:** Jumping straight to coding without understanding the log format; over-planning every schema field before real data shapes are known — keep schema "v1, expected to change."

### Phase 1 — Backend Core & Detection (Days 5–16, Pair 1)
**Objectives:** Build ingestion, normalization, persistence, the Sigma detection engine, MITRE ATT&CK mapping, incident grouping, and the core REST API.
**Deliverables:** Working API that ingests a log file and returns detected+MITRE-mapped incidents via curl/Postman, no frontend needed yet.
**Completion criteria:** 12–15 Sigma rules working against sample data; core endpoints (`/ingest`, `/incidents`, `/incidents/{id}`, `/mitre/techniques`) documented and testable.
**Common mistakes:** Building the RAG/AI layer before the detection pipeline is solid — Pair 2 needs real incidents to feed RAG, not fabricated ones, so keep Pair 2 informed of progress via daily sync.

### Phase 2 — AI / RAG Development (Days 5–16, Pair 2, parallel to Phase 1)
**Objectives:** Load the MITRE dataset, build the knowledge base, wire embeddings + ChromaDB, build the retrieval and generation chain, and build incident chat.
**Deliverables:** Given an incident ID, the API returns a grounded LLM explanation + recommended response; chat endpoint works.
**Completion criteria:** Explanations reference specific retrieved content (traceable to a knowledge base chunk), not generic LLM knowledge.
**Common mistakes:** Not testing for hallucination — spot-check that explanations match the actual technique, not a plausible-sounding wrong one. Since Phase 2 runs in parallel with Phase 1, the generation/chat work (which needs real incidents) should trail a few days behind the KB/retrieval work (which doesn't) — sync with Pair 1 around Day 11–13 once real incidents exist.

### Phase 3 — Frontend Development (Days 17–24, both pairs)
**Objectives:** Build dashboard, incident list/detail, MITRE heatmap, chat UI, log upload, rule management view. Days 17–20: each pair builds the frontend for its own backend/AI work. Days 21–24: pairs swap to polish/finish each other's UI and cross-review.
**Deliverables:** Fully working UI wired to the real API (no mock data).
**Completion criteria:** A non-technical viewer can navigate from "list of incidents" to "understand what happened and what to do" without narration; every team member has touched at least one screen they didn't originally build (via the Day 21–24 swap).
**Common mistakes:** Building UI against hardcoded mock JSON for too long — integrate with the real API from Day 17.

### Phase 4 — Testing (Days 25–27, whole team)
**Objectives:** Integration/E2E testing, malformed-input and LLM-failure-mode testing, RAG accuracy spot-checks, bug fixing.
**Deliverables:** Test notes, known-issues list, fixed critical bugs.
**Completion criteria:** Core user journey (upload log → see incidents → view explanation → chat) works reliably on sample data.
**Common mistakes:** Only testing the "happy path" — also test malformed logs, empty results, LLM API timeouts/errors.

### Phase 5 — Deployment (Days 28–29, both pairs)
**Objectives:** Dockerize backend, frontend, DB, and ChromaDB; write docker-compose; deployment guide; environment variable documentation; clean-machine test.
**Deliverables:** `docker compose up` works from a clean clone on a machine that isn't any team member's dev machine (test this literally).
**Completion criteria:** A teammate who didn't write the Dockerfiles can run the whole thing following only the README.
**Common mistakes:** "Works on my machine" — always test the actual clean-clone-and-run flow before calling it done.

### Phase 6 — Final Polish, Report & Presentation (Day 30, whole team)
**Objectives:** Demo rehearsal, final report, presentation slides, submission checklist.
**Deliverables:** Final report, presentation slides, demo script, polished README.
**Completion criteria:** The team can do a clean 10–15 minute demo without technical hiccups.
**Common mistakes:** Leaving all documentation/report writing to Day 30 — start the report skeleton during Phase 4 (Days 25–27) instead.
