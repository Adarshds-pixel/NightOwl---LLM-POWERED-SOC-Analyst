# NightOwl Engineering Handbook — Volume 2
## 120–126 Day Roadmap (Week-by-Week, Day-by-Day)

Rules for using this roadmap:
- Each day = 2–3 focused hours. Don't stack multiple days' tasks together.
- Every day ends with the **Daily Checklist**: (1) code compiles/runs, (2) task committed to Git with the listed message, (3) one sentence written in your own words about what you learned.
- **Weekly Review** (end of each week): re-read the week's commits, note anything you don't fully understand, add it to a "revisit" list.
- If a day's task isn't finished in the time box, it becomes tomorrow's first task — don't silently skip it.

Legend: **G**=Goal, **C**=Concept to learn, **T**=Coding task, **F**=Files/folders touched, **Commit**=Git commit message, **D**=Deliverable

--

## PHASE 0 — RESEARCH (Week 1, Days 1–7)
Milestone at end of week: you can explain Sysmon event types, Sigma rule structure, and MITRE ATT&CK's Tactic/Technique model without notes.

| Day | G | C | T | F | Commit | D | Time |
|---|---|---|---|---|---|---|---|
| 1 | Understand the problem space | What a SOC does; alert fatigue | Write a 1-page problem statement in your own words; set up GitHub repo | `docs/research/problem-statement.md` | `docs: add problem statement` | Problem statement doc | 2h |
| 2 | Understand Sysmon | Sysmon event IDs (1,3,5,7,10,11,22...) | Read Sysmon docs; tabulate top 10 event IDs and what they mean | `docs/research/sysmon-notes.md` | `docs: sysmon event id research` | Sysmon reference table | 2.5h |
| 3 | Understand EVTX format | Windows Event Log structure, XML schema | Download 1 sample EVTX (e.g. from a public Sysmon sample dataset); inspect with a viewer | `data/sample_logs/README.md` | `data: add sample evtx source notes` | Annotated sample log | 2h |
| 4 | Understand MITRE ATT&CK | Tactics vs Techniques vs Sub-techniques | Explore attack.mitre.org; pick 10 techniques relevant to endpoint detection | `docs/research/mitre-shortlist.md` | `docs: mitre technique shortlist` | Shortlist of 10 techniques | 2.5h |
| 5 | Understand Sigma rules | Sigma YAML syntax, `pySigma` library | Read Sigma spec; write 1 rule by hand (not yet code) for suspicious PowerShell | `docs/research/sigma-notes.md` | `docs: sigma rule research + first draft rule` | 1 hand-written Sigma rule | 2.5h |
| 6 | Understand RAG fundamentals | Embeddings, vector search, retrieval+generation | Read LangChain + ChromaDB quickstart docs; diagram the RAG flow for NightOwl | `docs/research/rag-notes.md` | `docs: rag pipeline research` | RAG flow diagram | 2.5h |
| 7 | Survey similar projects | Compare 2–3 open-source SOC/detection tools | Write comparison notes: what they do well / poorly vs your plan | `docs/research/competitive-scan.md` | `docs: competitive scan` | Comparison notes; Week 1 review | 2h |

---

## PHASE 1 — PLANNING (Week 2, Days 8–12)
Milestone: architecture, folder structure, and API endpoint list are finalized and won't meaningfully change during backend dev.

| Day | G | C | T | F | Commit | D | Time |
|---|---|---|---|---|---|---|---|
| 8 | Finalize architecture | System design basics: layering, separation of concerns | Confirm/adjust Vol.1 architecture diagram for your case; write decision rationale | `docs/architecture.md` | `docs: finalize v1 architecture` | Approved architecture doc | 2h |
| 9 | Finalize folder structure | Monorepo conventions | Scaffold empty backend/frontend folder tree from Vol.1 §3.3 | full repo skeleton | `chore: scaffold project structure` | Repo skeleton pushed | 2h |
| 10 | Design DB schema v1 | ERD basics, normalization | Draw ERD for events/alerts/incidents/rules/chat_messages | `docs/erd.png`, `docs/schema-v1.md` | `docs: db schema v1` | ERD + schema doc | 2.5h |
| 11 | Design API contract v1 | REST conventions | List all v1 endpoints (method, path, purpose, request/response shape) | `docs/api-spec-v1.md` | `docs: api spec v1` | Endpoint list table | 2.5h |
| 12 | Pick LLM provider | Comparing OpenAI/Claude/Gemini API for RAG use case | Sign up, get API key, test one basic API call from a script | `backend/scripts/test_llm.py` | `chore: verify llm api access` | Working test API call; Week 2 review | 2h |

---

## PHASE 2 — DESIGN (Week 3, Days 13–18)
Milestone: you have a rule template, a wireframe set, and a knowledge base source list — ready to start real coding.

| Day | G | C | T | F | Commit | D | Time |
|---|---|---|---|---|---|---|---|
| 13 | Detailed DB schema | SQLAlchemy modeling | Write SQLAlchemy models for all 5 core tables | `backend/app/models/*.py` | `feat: db models v1` | Models compile, no DB yet | 2.5h |
| 14 | Set up PostgreSQL + Alembic | Migrations | Docker-run Postgres locally; init Alembic; first migration | `backend/alembic/`, `docker-compose.yml` (db only) | `chore: postgres + alembic setup` | DB runs, migration applies | 2.5h |
| 15 | Sigma rule template | Rule authoring pattern | Write a NightOwl rule YAML template + 3 filled example rules | `backend/app/detection/rules/*.yml` | `feat: sigma rule template + 3 rules` | 3 draft rules | 2h |
| 16 | RAG knowledge base plan | Content curation for retrieval | List which MITRE technique docs + playbook docs will seed ChromaDB; draft 2 playbooks | `data/knowledge_base/playbooks/*.md` | `docs: knowledge base source plan + 2 playbooks` | KB source list + 2 playbooks | 2.5h |
| 17 | Dashboard wireframes | Low-fi UX design | Sketch (Figma/paper/Excalidraw) 4 screens: Dashboard, Incident List, Incident Detail, MITRE Heatmap | `docs/wireframes/` | `docs: dashboard wireframes` | 4 wireframe images | 2.5h |
| 18 | Design review | Self-critique | Re-read all Phase 1–2 docs; fix inconsistencies; finalize Volume-2-adjacent "design-final.md" | `docs/design-final.md` | `docs: design phase sign-off` | Signed-off design doc; Week 3 review | 2h |

---

## PHASE 3 — BACKEND DEVELOPMENT (Weeks 4–9, Days 19–55)
Milestone: a REST API that ingests a real log file and returns detected, MITRE-mapped incidents — testable via curl/Postman, no frontend needed.

### Week 4 (Days 19–25) — FastAPI skeleton + ingestion start
| Day | G | T | F | Commit |
|---|---|---|---|---|
| 19 | FastAPI app boots | `main.py`, health-check route, settings via `pydantic-settings` | `backend/app/main.py`, `core/config.py` | `feat: fastapi skeleton + health endpoint` |
| 20 | DB session wiring | SQLAlchemy engine/session, dependency injection pattern | `backend/app/db/session.py` | `feat: db session dependency` |
| 21 | EVTX parsing (first pass) | Use `python-evtx`/`Evtx` lib to read one sample file, print raw records | `backend/app/ingestion/evtx_reader.py` | `feat: raw evtx reading` |
| 22 | EVTX → JSON | Convert raw XML records to Python dicts | `backend/app/ingestion/evtx_reader.py` | `feat: evtx to json conversion` |
| 23 | Normalization schema | Define common event schema (Pydantic) | `backend/app/schemas/event.py` | `feat: normalized event schema` |
| 24 | Normalization mapping | Map Sysmon fields → common schema for event IDs 1,3,11 | `backend/app/ingestion/normalizer.py` | `feat: normalizer for core event ids` |
| 25 | Persist events | Save normalized events to Postgres via SQLAlchemy | `backend/app/services/event_service.py` | `feat: persist normalized events`; Week 4 review |

### Week 5 (Days 26–32) — Ingestion API + detection engine start
| Day | G | T | F | Commit |
|---|---|---|---|---|
| 26 | Ingest API endpoint | `POST /ingest` accepts EVTX upload, runs pipeline | `backend/app/api/routes_ingest.py` | `feat: ingest endpoint` |
| 27 | Ingest error handling | Handle malformed files, empty files, wrong format | `routes_ingest.py`, `ingestion/` | `fix: robust ingest error handling` |
| 28 | Sigma engine research spike | Evaluate `pySigma` integration approach | `backend/app/detection/README.md` | `docs: pysigma integration plan` |
| 29 | Rule loader | Load all `.yml` rules from `detection/rules/` at startup | `backend/app/detection/rule_loader.py` | `feat: sigma rule loader` |
| 30 | Rule evaluation engine v1 | Evaluate one event against loaded rules | `backend/app/detection/engine.py` | `feat: detection engine v1` |
| 31 | Wire detection into ingest pipeline | After normalize+persist, run detection, store matches as alerts | `services/event_service.py`, `models/alert.py` | `feat: detection wired into ingest flow` |
| 32 | Write 5 more Sigma rules | Cover process creation, network connection, file creation categories | `detection/rules/*.yml` | `feat: 5 additional detection rules`; Week 5 review |

### Week 6 (Days 33–39) — More detections + alert→incident grouping
| Day | G | T | F | Commit |
|---|---|---|---|---|
| 33 | 5 more Sigma rules | Reach 10 rules total; cover registry, scheduled task categories | `detection/rules/*.yml` | `feat: reach 10 detection rules` |
| 34 | Alert model + persistence | Save `alerts` table rows on rule match | `models/alert.py`, `services/detection_service.py` | `feat: alert persistence` |
| 35 | Incident grouping logic v1 | Group related alerts (same host+time window) into an incident | `services/incident_service.py` | `feat: incident grouping v1` |
| 36 | Incident model + persistence | `incidents` table, link alerts to incidents | `models/incident.py` | `feat: incident model + linking` |
| 37 | Severity scoring heuristic | Combine rule severity + technique tactic weight | `services/severity_service.py` | `feat: severity scoring v1` |
| 38 | Unit tests: detection engine | Test each rule against crafted sample events | `backend/tests/test_detection.py` | `test: detection engine unit tests` |
| 39 | Bug-fix day | Fix issues found by tests | various | `fix: detection engine bugfixes`; Week 6 review |

### Week 7 (Days 40–46) — MITRE ATT&CK mapping
| Day | G | T | F | Commit |
|---|---|---|---|---|
| 40 | Load MITRE ATT&CK dataset | Download official STIX/JSON ATT&CK dataset, parse into lookup table | `backend/app/mitre/loader.py` | `feat: mitre attck dataset loader` |
| 41 | Rule → technique mapping | Add `mitre_technique_id` field to each Sigma rule, validate against dataset | `detection/rules/*.yml`, `mitre/validator.py` | `feat: rule to technique mapping + validation` |
| 42 | Incident → technique aggregation | Roll up technique IDs from an incident's alerts | `services/incident_service.py` | `feat: incident mitre aggregation` |
| 43 | MITRE metadata endpoint | `GET /mitre/techniques` returns technique catalog for frontend heatmap later | `api/routes_mitre.py` | `feat: mitre techniques endpoint` |
| 44 | Incidents list endpoint | `GET /incidents` with filters (severity, status, date range) | `api/routes_incidents.py` | `feat: list incidents endpoint` |
| 45 | Incident detail endpoint | `GET /incidents/{id}` with alerts + events + mitre techniques | `api/routes_incidents.py` | `feat: incident detail endpoint` |
| 46 | Integration tests: ingest→incident flow | End-to-end test: sample file in, incidents with techniques out | `tests/test_ingest_flow.py` | `test: e2e ingestion to incident flow`; Week 7 review |

### Week 8 (Days 47–51) — Remaining rules + hardening
| Day | G | T | F | Commit |
|---|---|---|---|---|
| 47 | 5 more Sigma rules | Reach 15 rules; cover lateral movement / credential access categories | `detection/rules/*.yml` | `feat: reach 15 detection rules` |
| 48 | 5 more Sigma rules (stretch) | Reach 18–20 rules if time allows | `detection/rules/*.yml` | `feat: reach 18-20 detection rules` |
| 49 | API error handling pass | Consistent error responses, input validation across all routes | `api/*.py` | `fix: consistent api error handling` |
| 50 | Logging setup | Structured logging (Python `logging` + JSON formatter) across services | `core/logging.py` | `feat: structured logging` |
| 51 | Backend Phase 3 review | Re-test full flow manually with 2–3 different sample logs; fix regressions | various | `fix: phase 3 stabilization`; Week 8 review |

### Week 9 (Days 52–55) — Buffer / catch-up week
| Day | G | T | Commit |
|---|---|---|---|
| 52 | Catch-up day 1 | Finish any incomplete Week 4–8 task | `fix/feat: catch-up` |
| 53 | Catch-up day 2 | Same | `fix/feat: catch-up` |
| 54 | Refactor pass | Split any file that grew too large; improve naming per Vol.3 standards | `refactor: cleanup pre-ai-phase` |
| 55 | Phase 3 sign-off | Write `docs/phase3-summary.md`: what's built, known limitations | `docs: phase 3 sign-off` — **Milestone: Backend v1 complete** |

---

## PHASE 4 — AI DEVELOPMENT (Weeks 10–13, Days 56–75)
Milestone: given an incident ID, the API returns a grounded, non-hallucinated explanation + recommended response, and incident chat works.

### Week 10 (Days 56–61) — Knowledge base + embeddings
| Day | G | T | F | Commit |
|---|---|---|---|---|
| 56 | ChromaDB setup | Install, run locally, verify basic add/query | `backend/app/rag/chroma_client.py` | `feat: chromadb setup` |
| 57 | Sentence Transformers setup | Load embedding model, embed a test string | `backend/app/rag/embeddings.py` | `feat: embedding model wiring` |
| 58 | Knowledge base ingestion script | Chunk MITRE technique docs + playbooks, embed, store in Chroma | `backend/scripts/build_kb.py` | `feat: kb ingestion script` |
| 59 | Run KB build for real | Actually populate ChromaDB with all your MITRE docs + 5+ playbooks | `data/knowledge_base/` | `chore: populate vector db` |
| 60 | Retrieval function | Given a query, return top-k relevant chunks with scores | `backend/app/rag/retriever.py` | `feat: retrieval function` |
| 61 | Retrieval quality check | Manually test 10 queries, verify retrieved chunks make sense | `docs/research/retrieval-eval.md` | `test: manual retrieval quality check`; Week 10 review |

### Week 11 (Days 62–67) — Generation chain
| Day | G | T | F | Commit |
|---|---|---|---|---|
| 62 | LangChain prompt template | Design prompt: incident context + retrieved chunks → explanation | `backend/app/rag/prompts.py` | `feat: explanation prompt template` |
| 63 | LLM call wiring | Connect chosen provider's API via LangChain | `backend/app/rag/llm_client.py` | `feat: llm client wiring` |
| 64 | Explanation generation function | Combine retrieval + prompt + LLM call into one service function | `backend/app/rag/explain_service.py` | `feat: incident explanation generation` |
| 65 | Explain endpoint | `POST /incidents/{id}/explain` | `api/routes_incidents.py` | `feat: explain endpoint` |
| 66 | Response recommendation | Extend prompt to also produce a recommended response/playbook | `rag/prompts.py`, `rag/explain_service.py` | `feat: response recommendation` |
| 67 | Hallucination spot-check | Manually verify 10 generated explanations against ground truth; note failures | `docs/research/hallucination-eval.md` | `test: hallucination spot-check`; Week 11 review |

### Week 12 (Days 68–72) — Chat + refinement
| Day | G | T | F | Commit |
|---|---|---|---|---|
| 68 | Chat data model | `chat_messages` table + service | `models/chat_message.py`, `services/chat_service.py` | `feat: chat data model` |
| 69 | Chat endpoint v1 | `POST /incidents/{id}/chat` — retrieval scoped to incident context | `api/routes_chat.py` | `feat: incident chat endpoint` |
| 70 | Chat history endpoint | `GET /incidents/{id}/chat` returns message history | `api/routes_chat.py` | `feat: chat history endpoint` |
| 71 | Prompt refinement pass | Tune prompts based on Week 11 hallucination findings | `rag/prompts.py` | `fix: prompt refinement to reduce hallucination` |
| 72 | Error/timeout handling for LLM calls | Handle API timeouts, rate limits, malformed responses gracefully | `rag/llm_client.py` | `fix: llm call robustness`; Week 12 review |

### Week 13 (Days 73–75) — AI phase stabilization
| Day | G | T | Commit |
|---|---|---|---|
| 73 | Cost/latency check | Measure token usage and response time per explanation; document | `docs: llm cost and latency notes` |
| 74 | Regression test pass | Re-run Week 46 e2e test, now including explain + chat steps | `test: full pipeline regression` |
| 75 | Phase 4 sign-off | `docs/phase4-summary.md` | `docs: phase 4 sign-off` — **Milestone: AI layer complete** |

---

## PHASE 5 — FRONTEND DEVELOPMENT (Weeks 14–18, Days 76–100)
Milestone: a working dashboard wired to the real API — a non-technical viewer can navigate the whole flow unaided.

### Week 14 (Days 76–81) — Scaffold + API client
| Day | G | T | F | Commit |
|---|---|---|---|---|
| 76 | Vite + React + Tailwind scaffold | `npm create vite`, install Tailwind, verify dev server | `frontend/` | `chore: frontend scaffold` |
| 77 | Routing setup | React Router, page shells for Dashboard/Incidents/Detail/Heatmap | `frontend/src/pages/*.tsx` | `feat: routing + page shells` |
| 78 | API client | Axios/fetch wrapper matching backend API spec | `frontend/src/api/client.ts` | `feat: api client` |
| 79 | Layout + nav | App shell, sidebar/topnav, base design tokens (see Vol.3 design notes) | `frontend/src/components/Layout.tsx` | `feat: app layout + navigation` |
| 80 | Incident list — data wiring | Fetch real incidents from API, basic table/list render | `pages/IncidentList.tsx` | `feat: incident list wired to api` |
| 81 | Incident list — styling | Severity badges, status pills, sorting | `components/AlertCard.tsx` | `style: incident list polish`; Week 14 review |

### Week 15 (Days 82–87) — Incident detail + MITRE heatmap
| Day | G | T | F | Commit |
|---|---|---|---|---|
| 82 | Incident detail page — data | Fetch + render single incident with alerts/events | `pages/IncidentDetail.tsx` | `feat: incident detail wired to api` |
| 83 | Incident detail — explanation panel | Render LLM explanation + recommended response | `components/ExplanationPanel.tsx` | `feat: explanation panel` |
| 84 | MITRE heatmap — data | Fetch technique catalog + incident counts per technique | `pages/MitreHeatmap.tsx` | `feat: mitre heatmap data` |
| 85 | MITRE heatmap — visualization | Grid/heatmap visual (tactics as columns, techniques as cells) | `components/MitreGrid.tsx` | `feat: mitre heatmap visualization` |
| 86 | Dashboard summary page | Counts, recent incidents, severity distribution chart | `pages/Dashboard.tsx` | `feat: dashboard summary page` |
| 87 | Loading/empty/error states | Add across all pages built so far | various | `fix: loading and error states`; Week 15 review |

### Week 16 (Days 88–93) — Chat UI + rule management
| Day | G | T | F | Commit |
|---|---|---|---|---|
| 88 | Chat UI — layout | Chat panel component within incident detail | `components/ChatPanel.tsx` | `feat: chat ui layout` |
| 89 | Chat UI — wiring | Send message, display history, loading state while LLM responds | `components/ChatPanel.tsx` | `feat: chat wired to api` |
| 90 | Rule management page — list | List loaded Sigma rules, enabled/disabled state | `pages/RulesManager.tsx` | `feat: rules manager list view` |
| 91 | Rule management page — toggle | Enable/disable rule endpoint + UI wiring | `api/routes_rules.py`, `pages/RulesManager.tsx` | `feat: rule enable/disable` |
| 92 | Log upload UI | File upload component wired to `/ingest` | `components/LogUpload.tsx` | `feat: log upload ui` |
| 93 | Upload progress/feedback | Show ingestion progress/result (events parsed, alerts found) | `components/LogUpload.tsx` | `feat: upload feedback`; Week 16 review |

### Week 17 (Days 94–98) — Polish + responsiveness
| Day | G | T | Commit |
|---|---|---|---|
| 94 | Responsive design pass | Ensure usable on laptop screen sizes at minimum | `style: responsive layout fixes` |
| 95 | Accessibility pass | Color contrast for severity badges, keyboard nav for key actions | `style: accessibility improvements` |
| 96 | Empty-state / first-run experience | What a brand-new install looks like before any logs are uploaded | `feat: first-run empty states` |
| 97 | Visual design consistency pass | Consistent spacing, typography scale, color system (see Vol.3) | `style: design system consistency pass` |
| 98 | Cross-browser/manual QA | Test in Chrome + Firefox at minimum; log bugs | `docs: frontend qa notes`; Week 17 review |

### Week 18 (Days 99–100) — Frontend stabilization
| Day | G | T | Commit |
|---|---|---|---|
| 99 | Bug-fix day | Fix issues from Week 17 QA | `fix: frontend bugfixes` |
| 100 | Phase 5 sign-off | `docs/phase5-summary.md` | `docs: phase 5 sign-off` — **Milestone: Full stack demoable** |

---

## PHASE 6 — TESTING (Days 101–110)
| Day | G | T | Commit |
|---|---|---|---|
| 101 | Backend unit test coverage push | Fill gaps in detection/normalization/mitre test coverage | `test: expand backend unit coverage` |
| 102 | API integration test push | Cover all endpoints incl. error cases | `test: expand api integration coverage` |
| 103 | RAG accuracy testing | Run 20+ incidents through explain/chat, score accuracy manually | `docs: rag accuracy report` |
| 104 | Malformed input testing | Empty logs, corrupt EVTX, huge files — verify graceful handling | `fix: edge case handling` |
| 105 | LLM failure testing | Simulate API timeout/error, verify UI degrades gracefully | `fix: llm failure ux` |
| 106 | Full E2E manual run #1 | Fresh clone, fresh DB, full user journey, log every friction point | `docs: e2e test run 1 notes` |
| 107 | Bug-fix day 1 | Fix issues from Day 106 | `fix: e2e bugfixes round 1` |
| 108 | Full E2E manual run #2 | Repeat with a different sample log set | `docs: e2e test run 2 notes` |
| 109 | Bug-fix day 2 | Fix issues from Day 108 | `fix: e2e bugfixes round 2` |
| 110 | Testing sign-off | `docs/testing-report.md` | `docs: testing phase sign-off` — **Milestone: Core journey reliable** |

---

## PHASE 7 — DEPLOYMENT (Days 111–118)
| Day | G | T | Commit |
|---|---|---|---|
| 111 | Backend Dockerfile | Multi-stage build, non-root user, healthcheck | `backend/Dockerfile` | `chore: backend dockerfile` |
| 112 | Frontend Dockerfile | Build + serve static assets | `frontend/Dockerfile` | `chore: frontend dockerfile` |
| 113 | docker-compose.yml — full stack | backend, frontend, db, chroma, networks, volumes | `docker-compose.yml` | `chore: full docker-compose stack` |
| 114 | Environment variable audit | `.env.example`, document every required variable | `.env.example`, `docs/env-vars.md` | `docs: env var documentation` |
| 115 | Clean-machine test #1 | Fresh clone on a different machine/VM, `docker compose up`, fix issues | various | `fix: clean deploy issues round 1` |
| 116 | Clean-machine test #2 | Repeat after fixes | various | `fix: clean deploy issues round 2` |
| 117 | Deployment guide | Step-by-step doc a stranger could follow | `docs/deployment-guide.md` | `docs: deployment guide` |
| 118 | Deployment sign-off | Final verification | — | `chore: deployment phase sign-off` — **Milestone: One-command deploy works** |

---

## PHASE 8 — MAINTENANCE, FINAL REPORT & PRESENTATION (Days 119–126)
| Day | G | T | Commit |
|---|---|---|---|
| 119 | Demo rehearsal #1 | Run full demo end-to-end, time it, note stumbles | `docs: demo rehearsal 1 notes` |
| 120 | Fix demo stumbles | Fix issues found in rehearsal | `fix: demo rehearsal fixes` |
| 121 | Final report — draft | Use Volume 3 report template, fill in all sections | `docs/final-report.md` | `docs: final report draft` |
| 122 | Final report — review | Proofread, verify all claims match actual working features | `docs/final-report.md` | `docs: final report revisions` |
| 123 | Presentation slides | Build slide deck (problem, architecture, demo, results, future work) | `docs/presentation/` | `docs: presentation slides` |
| 124 | Demo rehearsal #2 | Full run with slides + live demo, time it again | — | `docs: demo rehearsal 2 notes` |
| 125 | README + docs final polish | Ensure README is the front door: what/why/how to run | `README.md` | `docs: final readme polish` |
| 126 | Project completion sign-off | Final checklist (Volume 3 §12) fully checked | — | `chore: project complete` — **Milestone: Submission ready** |

---

## Milestones Summary
| Day | Milestone |
|---|---|
| 7 | Research complete |
| 18 | Design finalized |
| 55 | Backend v1 complete |
| 75 | AI layer complete |
| 100 | Full stack demoable |
| 110 | Core journey reliable |
| 118 | One-command deploy works |
| 126 | Submission ready |

## Notes on Flexibility
- This roadmap totals 126 working days. If you have 120–130 calendar-equivalent working sessions, you have built-in slack — Weeks 9 and parts of Phase 6/7 already function as buffers.
- If a week runs long, borrow from Phase 8 (final polish) time before cutting Phase 3 (backend) or Phase 6 (testing) time — a working, tested core matters more for a viva than a polished-but-shaky demo.
