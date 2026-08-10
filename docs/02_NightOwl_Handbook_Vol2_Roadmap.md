# NightOwl Engineering Handbook — Volume 2
## 30-Day Roadmap (Team of 4, Two Rotating Pairs)

## Team & Rotation Model
Two pairs, 2 members each — swap in real names once assigned:
- **Pair 1** = Member A + Member B
- **Pair 2** = Member C + Member D

Pairs work in parallel through most of the project rather than one person moving sequentially through every task. They **rotate**: Pair 1 starts on Backend/Detection and Pair 2 starts on AI/RAG, then at the Frontend stage (Days 15–22) both pairs build UI for their own APIs first, then **swap to polish/finish each other's UI** — so by Day 22 every member has touched at least two of {backend, AI/RAG, frontend}, and both pairs collectively cover all three.

| Days | Block | Pair 1 focus | Pair 2 focus |
|---|---|---|---|
| 1–2 | Research & Planning & Design | Internalize existing research, finalize architecture, lock backend scaffold | Finalize DB schema, API contract, wireframes, free-tier LLM lock |
| 3–8 | Core Build A | Backend: FastAPI, EVTX ingestion, normalization, persistence | AI/RAG foundation: MITRE dataset loader, knowledge base build, embeddings, retrieval |
| 9–14 | Core Build B | Detection engine, 12–15 Sigma rules, incident grouping, MITRE mapping, core API endpoints | RAG generation chain with self-critique (explain endpoint, source attribution) + chat, using Pair 1's incidents as they come online |
| 15–18 | Frontend A | Frontend for their own APIs: incident list/detail, MITRE heatmap | Frontend for their own APIs: chat UI, explanation panel w/ source attribution, log upload, rules manager |
| 19–22 | Frontend B (swap + polish) | Polish/finish Pair 2's chat UI + cross-review; responsive/accessibility pass | Polish/finish Pair 1's incident views + heatmap; cross-review; QA |
| 23–25 | Integration & Testing | Whole team, mixed sub-groups | Whole team, mixed sub-groups |
| 26–27 | Deployment | Backend/DB/Chroma Docker + compose | Frontend Docker + compose + deployment guide |
| 28–30 | Demo, Report & Presentation | Whole team: curated demo dataset, demo script, two rehearsals, final report, slides, sign-off | |

**Rules for using this roadmap:**
- Each day = 2–3 focused hours **per member**, worked together within each pair (pair programming or split sub-tasks, reconvening same day).
- Every day ends with the **Daily Checklist**: (1) code compiles/runs, (2) task committed to Git with the listed message, (3) one sentence per pair written in your own words about what you learned.
- **Block Review** (end of each block above): both pairs re-read the block's commits together, note anything unclear, add it to a shared "revisit" list.
- If a day's task isn't finished in the time box, it becomes tomorrow's first task for that pair — don't silently skip it.
- **Sync points**: because the pairs' work depends on each other at a few points (Pair 2 needs Pair 1's real incidents from ~Day 11; Pair 2 needs Pair 1's frontend scaffold on Day 15; both pairs swap codebases on Day 19), do a short async standup (5–10 min, chat is fine) at the start of each day near those boundaries — don't wait for the block review to discover a blocker.
- **LLM policy: free-tier only, no paid API usage anywhere in this project** (see Day 2). The rest of the stack (FastAPI, Postgres, ChromaDB, embeddings, React, Docker) is already $0 — this keeps the whole project at $0 to build and run.

---

## PHASE 0 — RESEARCH, PLANNING & DESIGN (Days 1–2, whole team)
Milestone at end of block: architecture, DB schema v1, and API contract v1 are finalized. Note: the underlying research (Sysmon event types, Sigma rule structure, MITRE ATT&CK's Tactic/Technique model, RAG fundamentals) is already captured in this handbook — these 2 days are for the team to internalize it and lock the concrete artifacts, not research from scratch.

| Day | Pair 1 | Pair 2 | Commit | Deliverable |
|---|---|---|---|---|
| 1 | Finalize architecture diagram + decision rationale (confirm/adjust Volume 1 §3.1 for the team); scaffold backend folder tree (Volume 1 §3.3); hands-on inspect 1 sample EVTX file to confirm the documented event-ID understanding | Design DB schema v1 (ERD for events/alerts/incidents/rules/chat_messages); draft API contract v1 (endpoint list: method, path, purpose, shapes) | `docs: finalize architecture + db schema v1 + api spec v1`; `chore: scaffold repo` | `docs/architecture.md`, repo skeleton, `docs/erd.png` + `docs/schema-v1.md`, `docs/api-spec-v1.md`. **Whole team:** set up the GitHub repo + branch strategy, lock in real pair member names |
| 2 | Pick + test a **free-tier** LLM provider (Gemini free tier or Groq — explicitly no paid API for this project); Sigma rule YAML template + 3 example rules | Dashboard wireframes (4 screens: Dashboard, Incident List, Incident Detail, MITRE Heatmap); knowledge base source list + draft 2 playbooks | `chore: verify free-tier llm api access`; `feat: sigma rule template`; `docs: wireframes + kb plan` | Working free-tier LLM test call, 3 draft rules, 4 wireframes, KB source list + 2 playbooks. **Whole team:** sign off `docs/design-final.md` — **Milestone: Research/Planning/Design complete** |

---

## PHASE 1 — BACKEND CORE & DETECTION (Days 3–14, Pair 1)
Milestone: a REST API that ingests a real log file and returns detected, MITRE-mapped incidents — testable via curl/Postman.

| Day | Goal | Task | Files | Commit |
|---|---|---|---|---|
| 3 | FastAPI boots + DB session wiring | `main.py`, health-check route, settings via `pydantic-settings`; SQLAlchemy engine/session + dependency injection pattern | `backend/app/main.py`, `core/config.py`, `db/session.py` | `feat: fastapi skeleton + db session dependency` |
| 4 | DB models + migrations | SQLAlchemy models for all 5 core tables; Postgres via Docker locally; init Alembic, first migration | `backend/app/models/*.py`, `backend/alembic/`, `docker-compose.yml` (db only) | `feat: db models v1 + postgres/alembic setup` |
| 5 | EVTX parsing | Read one sample file with `python-evtx`/`Evtx`, print raw records; convert raw XML records to Python dicts (JSON) | `backend/app/ingestion/evtx_reader.py` | `feat: evtx reading + json conversion` |
| 6 | Normalization + persistence | Define common event schema (Pydantic); map Sysmon fields → common schema for event IDs 1, 3, 11; save normalized events to Postgres | `backend/app/schemas/event.py`, `backend/app/ingestion/normalizer.py`, `backend/app/services/event_service.py` | `feat: normalized event schema + persistence` |
| 7 | Ingest API | `POST /ingest` accepts EVTX upload, runs pipeline; handle malformed/empty/wrong-format files | `backend/app/api/routes_ingest.py` | `feat: ingest endpoint + robust error handling` |
| 8 | Detection engine v1 | Evaluate `pySigma` integration approach; load all `.yml` rules from `detection/rules/` at startup; evaluate one event against loaded rules; wire detection into ingest pipeline | `backend/app/detection/rule_loader.py`, `backend/app/detection/engine.py`, `services/event_service.py` | `feat: sigma rule loader + detection engine v1 wired into ingest` — **end of Core Build A** |
| 9 | 5 Sigma rules + alerts | Cover process creation, network connection, file creation categories; save `alerts` table rows on rule match | `detection/rules/*.yml`, `models/alert.py`, `services/detection_service.py` | `feat: 5 detection rules + alert persistence` |
| 10 | 5 more rules (10 total) + incident grouping | Cover registry, scheduled task categories; group related alerts (same host + time window) into an incident; `incidents` table + linking | `detection/rules/*.yml`, `services/incident_service.py`, `models/incident.py` | `feat: reach 10 rules + incident grouping v1` |
| 11 | Severity scoring + unit tests | Combine rule severity + technique tactic weight; test each rule against crafted sample events | `services/severity_service.py`, `backend/tests/test_detection.py` | `feat: severity scoring v1`; `test: detection engine unit tests` — **sync: tell Pair 2 real incidents now exist** |
| 12 | MITRE mapping | Add `mitre_technique_id` to each rule, validate against Pair 2's loaded MITRE dataset; roll up technique IDs from an incident's alerts | `detection/rules/*.yml`, `mitre/validator.py`, `services/incident_service.py` | `feat: rule-to-technique mapping + incident mitre aggregation` |
| 13 | Incident endpoints | `GET /incidents` with filters (severity, status, date range); `GET /incidents/{id}` with alerts + events + mitre techniques | `api/routes_incidents.py` | `feat: list + detail incident endpoints` |
| 14 | Hardening + sign-off | 5 more rules (lateral movement / credential access → 15 total); consistent API error handling across routes; structured JSON logging; end-to-end integration test (sample file in, incidents+techniques out) | `detection/rules/*.yml`, `api/*.py`, `core/logging.py`, `tests/test_ingest_flow.py` | `feat: reach 15 rules`; `fix: consistent error handling`; `feat: structured logging`; `test: e2e ingestion to incident flow`; `docs: backend phase sign-off` — **Milestone: Backend + Detection core complete** |

---

## PHASE 2 — AI / RAG DEVELOPMENT (Days 3–14, Pair 2, parallel to Phase 1)
Milestone: given an incident ID, the API returns a grounded, self-checked explanation with source attribution + a recommended response, and incident chat works.

| Day | Goal | Task | Files | Commit |
|---|---|---|---|---|
| 3 | ChromaDB + embeddings setup | Install/run ChromaDB locally, verify basic add/query; load a Sentence Transformers embedding model, embed a test string | `backend/app/rag/chroma_client.py`, `backend/app/rag/embeddings.py` | `feat: chromadb + embedding model setup` |
| 4 | MITRE dataset loader | Download the official MITRE ATT&CK STIX/JSON dataset, parse into a lookup table (also feeds Pair 1's rule-to-technique validation later) | `backend/app/mitre/loader.py` | `feat: mitre attck dataset loader` |
| 5 | Knowledge base build | Chunk MITRE technique docs + playbooks, embed, store in Chroma; run the build for real (populate with all MITRE docs + 5+ playbooks) | `backend/scripts/build_kb.py`, `data/knowledge_base/` | `feat: kb ingestion script`; `chore: populate vector db` |
| 6 | Retrieval | Given a query, return top-k relevant chunks with scores; manually test 10 queries and verify retrieved chunks make sense | `backend/app/rag/retriever.py`, `docs/research/retrieval-eval.md` | `feat: retrieval function`; `test: manual retrieval quality check` |
| 7 | MITRE endpoint + validator prep | `GET /mitre/techniques` returns technique catalog (for the heatmap + Pair 1's rule validation); scaffold the `mitre/validator.py` interface Pair 1 will use on Day 12 | `api/routes_mitre.py`, `mitre/validator.py` | `feat: mitre techniques endpoint + validator scaffold` |
| 8 | Prompt + LLM wiring | Design the explanation prompt (incident context + retrieved chunks → explanation); connect the free-tier provider's API via LangChain | `backend/app/rag/prompts.py`, `backend/app/rag/llm_client.py` | `feat: explanation prompt template + llm client wiring` — **end of Core Build A** |
| 9 | Explanation generation **with self-critique** | Combine retrieval + prompt + LLM call into one service function that runs **retrieve → draft explanation → self-check pass** (the LLM verifies its own draft against the retrieved chunks and flags low-confidence claims before returning) — test against Pair 1's early alerts, or mocked incident data if Pair 1 isn't there yet | `backend/app/rag/explain_service.py` | `feat: incident explanation generation with self-critique step` |
| 10 | Explain endpoint **with source attribution** | `POST /incidents/{id}/explain` — response includes the explanation, recommended response, **and the retrieved source chunks + similarity scores** (for the frontend's source-attribution UI on Day 16); extend the prompt to also produce a recommended response/playbook | `api/routes_incidents.py`, `rag/prompts.py`, `rag/explain_service.py` | `feat: explain endpoint + response recommendation + source attribution` |
| 11 | Hallucination spot-check | Manually verify 10 generated explanations against ground truth using Pair 1's now-real incidents; note failures — the self-critique step (Day 9) should reduce but not eliminate hallucination, so this check still matters | `docs/research/hallucination-eval.md` | `test: hallucination spot-check` — **sync: pull fresh incidents from Pair 1** |
| 12 | Chat data + endpoint | `chat_messages` table + service; `POST /incidents/{id}/chat` with retrieval scoped to incident context | `models/chat_message.py`, `services/chat_service.py`, `api/routes_chat.py` | `feat: chat data model + incident chat endpoint` |
| 13 | Chat history + prompt refinement | `GET /incidents/{id}/chat` returns message history; tune prompts based on Day 11 hallucination findings | `api/routes_chat.py`, `rag/prompts.py` | `feat: chat history endpoint`; `fix: prompt refinement to reduce hallucination` |
| 14 | Robustness + sign-off | Handle LLM API timeouts, rate limits, malformed responses gracefully (free-tier providers have tighter rate limits — cache responses during repeated testing); measure token usage and response time per explanation, document | `rag/llm_client.py`, `docs/llm-cost-latency.md` | `fix: llm call robustness`; `docs: ai phase sign-off` — **Milestone: AI/RAG core complete** |

---

## PHASE 3 — FRONTEND DEVELOPMENT (Days 15–22, both pairs)
Milestone: a working dashboard wired to the real API — a non-technical viewer can navigate the whole flow unaided.

### Days 15–18 — each pair builds the frontend for its own work
| Day | Pair 1 (backend/detection UI) | Pair 2 (AI/RAG UI) | Commit |
|---|---|---|---|
| 15 | **Morning:** Vite + React + Tailwind scaffold, routing + page shells (Dashboard/Incidents/Detail/Heatmap), API client wrapper — merge by end of day so Pair 2 can build on it. **Afternoon:** app layout + nav (sidebar/topnav, design tokens) | Chat panel component skeleton (`ChatPanel.tsx`) + log upload component wired to `/ingest`, built against the merging scaffold | `chore: frontend scaffold + routing + api client`; `feat: app layout + nav`; `feat: chat panel skeleton + log upload ui` |
| 16 | Incident list — fetch real incidents, basic table/list render | Chat UI wiring — send message, display history, loading state while LLM responds; explanation panel rendering the LLM explanation + recommended response **+ the retrieved source chunks and similarity scores (source-attribution UI)** | `feat: incident list wired to api`; `feat: chat wired to api + explanation panel with source attribution` |
| 17 | Incident list styling (severity badges, status pills, sorting); incident detail page — fetch + render single incident with alerts/events | Upload progress/feedback (events parsed, alerts found); loading/empty/error states across chat + upload | `style: incident list polish`; `feat: incident detail wired to api`; `feat: upload feedback + error states` |
| 18 | MITRE heatmap — fetch technique catalog + incident counts, grid visualization (tactics as columns); dashboard summary page (counts, recent incidents, severity chart) | Rules manager page — list loaded Sigma rules with enabled/disabled state, wired to a small new `api/routes_rules.py` enable/disable endpoint | `feat: mitre heatmap + dashboard summary`; `feat: rules manager list + enable/disable` |

### Days 19–22 — swap, polish, cross-review
| Day | Pair 1 | Pair 2 | Commit |
|---|---|---|---|
| 19 | Cross-review Pair 2's chat/explanation/upload code; responsive design pass on incident + heatmap pages (usable at laptop sizes) | Cross-review Pair 1's incident/heatmap/dashboard code; accessibility pass (color contrast for severity badges, keyboard nav for key actions) | `fix: responsive layout fixes (review + own pages)`; `style: accessibility improvements` — **sync: pairs swap codebases** |
| 20 | Fix bugs found in Pair 2's chat/upload UI during review; polish chat UX | Fix bugs found in Pair 1's incident/heatmap UI during review; polish heatmap visualization | `fix: cross-review bugfixes (chat/upload)`; `fix: cross-review bugfixes (incident/heatmap)` |
| 21 | First-run / empty-state experience across all pages (brand-new install, no logs uploaded yet); visual design consistency pass (spacing, typography, color system) | Cross-browser/manual QA (Chrome + Firefox minimum); log bugs found | `feat: first-run empty states`; `style: design consistency pass`; `docs: frontend qa notes` |
| 22 | **Whole team:** bug-fix day from Day 21 QA notes; Phase 3 sign-off `docs/frontend-phase-summary.md` | | `fix: frontend bugfixes`; `docs: frontend phase sign-off` — **Milestone: Full stack demoable** |

---

## PHASE 4 — INTEGRATION & TESTING (Days 23–25, whole team, mixed sub-groups)
Mix pair membership for this block (e.g. one person from each original pair per sub-group) so testing isn't done only by the people who wrote the code.

| Day | Focus | Task | Commit |
|---|---|---|---|
| 23 | Coverage push | Backend unit/integration test coverage (detection, normalization, mitre, all API endpoints incl. error cases); RAG accuracy testing (run 20+ incidents through explain/chat, score manually) | `test: expand backend + api test coverage`; `docs: rag accuracy report` |
| 24 | Edge cases + E2E run 1 | Malformed input testing (empty logs, corrupt EVTX, huge files); LLM failure testing (simulate timeout/error, verify UI degrades gracefully); full E2E manual run on a fresh clone/fresh DB, log every friction point | `fix: edge case + llm failure handling`; `docs: e2e test run 1 notes` |
| 25 | Bug-fix + E2E run 2 + sign-off | Fix issues from Day 24; repeat E2E run with a different sample log set; testing sign-off | `fix: e2e bugfixes`; `docs: testing report + phase sign-off` — **Milestone: Core journey reliable** |

---

## PHASE 5 — DEPLOYMENT (Days 26–27, both pairs)
| Day | Pair 1 | Pair 2 | Commit |
|---|---|---|---|
| 26 | Backend Dockerfile (multi-stage, non-root user, healthcheck) + db/chroma service config | Frontend Dockerfile (build + serve static assets) + `docker-compose.yml` full stack (backend, frontend, db, chroma, networks, volumes) — joint file, both pairs review | `chore: backend dockerfile + db/chroma config`; `chore: frontend dockerfile + full docker-compose stack` |
| 27 | Clean-machine test #1 (fresh clone on a machine neither pair developed on, `docker compose up`, fix issues) | Environment variable audit (`.env.example`, `docs/env-vars.md`); deployment guide (`docs/deployment-guide.md`); clean-machine test #2 (repeat after fixes) | `fix: clean deploy issues`; `docs: env vars + deployment guide` — **Milestone: One-command deploy works** |

---

## PHASE 6 — DEMO, FINAL REPORT & PRESENTATION (Days 28–30, whole team)
This block was deliberately expanded from 1 day to 3 (freed up by compressing Phase 0 from 4 days to 2 — see "Notes on Flexibility" below) because a professional demo needs its own script, a dataset curated to look good live, and at least two separated rehearsals with fix-time between them, not one day doing discovery and fixing at once.

| Day | Task | Owner | Commit |
|---|---|---|---|
| 28 | **Curate a demo dataset** — craft/select an EVTX sample that reliably triggers a good spread of severities and MITRE tactics across the 12–15 rules (not whatever was used for ad-hoc testing). **Write a demo script** — step-by-step: upload → incident list → open a high-severity incident → explanation with source attribution + self-critique note → MITRE heatmap → chat follow-up — explicitly working the two standout features into the narration. **Rehearsal #1** — run the full script end-to-end, time it, note every stumble | Whole team | `docs: demo dataset + demo script`; `docs: rehearsal 1 notes` |
| 29 | Fix stumbles from Rehearsal #1. **Rehearsal #2** — repeat with fixes, time it again. Record a backup video/screenshots as a live-demo fallback. Start the final report draft (Volume 3 §9.7 template, fill in all sections) | Whole team, split by section | `fix: demo rehearsal 1 fixes`; `docs: rehearsal 2 notes + demo fallback recording`; `docs: final report draft` |
| 30 | Finish final report + proofread against actual working features. Presentation slides (problem, architecture, live demo, results/metrics — including RAG accuracy and "$0 to run" as a talking point — future work). README final polish. Project completion sign-off (Volume 3 §12 checklist, fully checked) | Whole team | `docs: final report + presentation slides`; `docs: final readme polish`; `chore: project complete` — **Milestone: Submission ready** |

---

## Milestones Summary
| Day | Milestone |
|---|---|
| 2 | Research / Planning / Design complete |
| 14 | Backend + Detection core complete (Pair 1) and AI/RAG core complete (Pair 2) |
| 22 | Full stack demoable |
| 25 | Core journey reliable |
| 27 | One-command deploy works |
| 30 | Submission ready |

## Notes on Flexibility
- This roadmap assumes ~2–3 focused hours/day per member, worked in parallel by two pairs — the point of compressing 126 solo days into 30 team days is parallelism, not a smaller scope. Phase 0 was deliberately trimmed from 4 days to 2 (the team's research is already captured in this handbook, so Days 1–2 lock artifacts rather than research from scratch) — those 2 freed days were moved to Phase 6, which now gets 3 dedicated days for demo script, curated dataset, and two rehearsals. **Phase 6's 3 days are load-bearing for demo quality — if an earlier phase overruns, borrow from Phase 3 polish (Days 19–22) instead of cutting into Phase 6.**
- Sigma rule target is intentionally **12–15** (not the stretch 18–20 from a solo timeline) — flagged here as a deliberate scope re-pacing decision, not a silent cut. If Pair 1 finishes early, extra rules are the first thing to add back.
- If a hand-off sync point (Day 11, Day 15, Day 19) reveals a blocker — e.g. Pair 1's incidents aren't ready for Pair 2's hallucination check — don't silently wait; flag it same-day and adjust the next 1–2 days' tasks rather than letting both pairs drift out of sync.
