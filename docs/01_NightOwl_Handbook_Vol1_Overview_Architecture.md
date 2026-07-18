# NightOwl — AI-Powered Security Operations Center
## Engineering Handbook — Volume 1: Overview, AI Collaboration Rules, Architecture, SDLC

**Project type:** Final Year Major Project (Solo, AI-assisted)
**Duration:** 120–130 days
**Status:** Pre-development / Planning baseline (Day 0)

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
You are acting as a **pairing senior engineer and mentor**, not an autocomplete tool. The developer is a student who is learning while building. Your job is to make sure they understand *why*, not just *what*.

### 2.2 Hard rules — the AI must NOT:
- Skip explanations of *why* a design or code choice was made.
- Generate large, unreviewed blocks of code the developer didn't ask for.
- Over-engineer (no premature microservices, no unnecessary abstraction layers, no adding Kubernetes/Kafka/etc. to a solo 120-day student project).
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

### Phase 0 — Research (Days 1–7)
**Objectives:** Understand Sysmon/EVTX format, MITRE ATT&CK structure, Sigma rule syntax, RAG fundamentals, and survey 2–3 similar open-source SOC/detection projects.
**Deliverables:** Research notes doc; list of 15–20 candidate detection rules; chosen LLM provider decision with justification.
**Completion criteria:** Can explain, from memory, what an EVTX Event ID 1 vs 3 vs 11 means, and what a Sigma rule looks like.
**Common mistakes:** Jumping straight to coding without understanding the log format — leads to a fragile parser rewritten twice.

### Phase 1 — Planning (Days 8–12)
**Objectives:** Finalize architecture, folder structure, DB schema v1, API contract v1 (endpoint list), and the full roadmap (Volume 2).
**Deliverables:** Finalized architecture diagram, ERD, API spec draft (even informal, e.g. a markdown table of endpoints).
**Completion criteria:** You could hand this plan to another developer and they'd understand what to build.
**Common mistakes:** Over-planning every table/field before knowing real data shapes from Phase 0 — keep schema "v1, expected to change."

### Phase 2 — Design (Days 13–18)
**Objectives:** Detailed DB schema, detection rule format decision, RAG knowledge base content plan, low-fidelity dashboard wireframes.
**Deliverables:** Finalized ERD, 3–5 wireframe screens, rule YAML template, knowledge base source list.
**Completion criteria:** Confident enough in the design that backend coding won't require major schema rewrites.
**Common mistakes:** Skipping wireframes "because it's just a student project" — leads to messy, undirected frontend work later.

### Phase 3 — Backend Development (Days 19–55)
**Objectives:** Build ingestion, normalization, detection engine, MITRE mapping, REST API, DB layer.
**Deliverables:** Working API that can ingest a log file and return detected+mapped incidents via Postman/curl, no frontend needed yet.
**Completion criteria:** 15+ Sigma rules working against sample data; API endpoints documented and testable.
**Common mistakes:** Building the RAG/AI layer before the detection pipeline is solid — you need real incidents to feed RAG, not fabricated ones.

### Phase 4 — AI Development (Days 56–75)
**Objectives:** Build the knowledge base, embedding pipeline, ChromaDB integration, LangChain retrieval+generation chain, incident chat.
**Deliverables:** Given an incident ID, API returns a grounded LLM explanation + recommended response; chat endpoint works.
**Completion criteria:** Explanations reference specific retrieved content (can be traced back to a knowledge base chunk), not generic LLM knowledge.
**Common mistakes:** Not testing for hallucination — always spot-check that the explanation matches the actual technique, not a plausible-sounding wrong one.

### Phase 5 — Frontend Development (Days 76–100)
**Objectives:** Build dashboard, incident list/detail, MITRE heatmap, chat UI, rule management view.
**Deliverables:** Fully working UI wired to the real API (no more mock data).
**Completion criteria:** A non-technical viewer can navigate from "list of incidents" to "understand what happened and what to do" without your narration.
**Common mistakes:** Building UI against hardcoded mock JSON for too long — integrate with the real API early and often (start around day 80, not day 95).

### Phase 6 — Testing (Days 101–110)
**Objectives:** Unit tests (detection rules, parsers), integration tests (API endpoints), manual E2E testing, RAG accuracy spot-checks.
**Deliverables:** Test report, known-issues list, fixed critical bugs.
**Completion criteria:** Core user journey (upload log → see incidents → view explanation → chat) works reliably 10/10 times on sample data.
**Common mistakes:** Only testing the "happy path" — also test malformed logs, empty results, LLM API timeouts/errors.

### Phase 7 — Deployment (Days 111–118)
**Objectives:** Dockerize everything, write docker-compose, deployment guide, environment variable documentation.
**Deliverables:** `docker compose up` works from a clean clone on a fresh machine (test this literally).
**Completion criteria:** A friend with Docker installed and an LLM API key can run the whole thing following only the README.
**Common mistakes:** "Works on my machine" — always test the actual clean-clone-and-run flow before calling it done.

### Phase 8 — Maintenance / Final Polish (Days 119–125+)
**Objectives:** Bug fixes from demo rehearsals, final report writing, presentation prep, documentation polish.
**Deliverables:** Final report, presentation slides, demo script, polished README.
**Completion criteria:** You can do a clean 10–15 minute demo without technical hiccups.
**Common mistakes:** Leaving documentation/report writing entirely to the last week — start the final report skeleton by Phase 6.
