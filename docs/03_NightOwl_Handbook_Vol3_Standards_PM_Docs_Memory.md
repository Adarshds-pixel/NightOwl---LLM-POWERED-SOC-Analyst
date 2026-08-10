# NightOwl Engineering Handbook — Volume 3
## Coding Standards, Project Management, Documentation Templates, AI Memory, Checklists

---

## SECTION 6 — AI CODING RULES (for any AI assistant generating code in this repo)

When generating code, the AI must:
- Follow **SOLID** principles — especially single-responsibility: one file/function/class does one job.
- Write **modular** code — no giant "do everything" service files.
- Keep **business logic** out of API route handlers; routes call `services/`, services call `models/`/external clients.
- Match the folder structure in Volume 1 §3.3 — new files go where the pattern says, not wherever is convenient.
- Comment only where the *why* isn't obvious from the code itself. Don't narrate obvious lines.
- Use **type hints** everywhere in Python (`def foo(x: int) -> str:`), and TypeScript (not plain `.js`) on the frontend.
- **Validate inputs** at the boundary (Pydantic schemas for API requests; never trust raw request bodies).
- **Handle errors explicitly** — no bare `except:`; catch specific exceptions, return meaningful HTTP error codes.
- Never generate a file over ~200–300 lines without proposing a split.
- Prefer several small, reusable, testable functions over one large function.
- After generating any non-trivial code, explain: what it does, why this approach, and one alternative that was considered and rejected.
- Any RAG/explanation code must preserve the two standout features (Volume 1 §1.5a, §3.7): the **self-critique step** (draft explanation → self-check against retrieved chunks before returning) and **source attribution** (retrieved chunks + similarity scores returned alongside the explanation, not just used internally). Don't quietly simplify these away to "just get it working" — flag it first if a tradeoff seems necessary.
- LLM provider calls must go through a free-tier provider only (Volume 1 §3.9) — never wire in a paid API by default.

---

## SECTION 7 — CODING STANDARDS

### Naming Conventions
| Item | Convention | Example |
|---|---|---|
| Python files/modules | `snake_case` | `evtx_reader.py` |
| Python classes | `PascalCase` | `EventNormalizer` |
| Python functions/vars | `snake_case` | `normalize_event()` |
| TypeScript files (components) | `PascalCase.tsx` | `IncidentDetail.tsx` |
| TypeScript files (utils/hooks) | `camelCase.ts` | `useIncidents.ts` |
| React components | `PascalCase` | `AlertCard` |
| React hooks | `useCamelCase` | `useIncidentChat` |
| DB tables | `snake_case`, plural | `chat_messages` |
| DB columns | `snake_case` | `mitre_technique_id` |
| API routes | `kebab-case`, plural nouns | `/api/v1/incidents`, `/api/v1/chat-messages` |
| Sigma rule files | `snake_case.yml`, named after behavior | `suspicious_powershell_encoded.yml` |

### Folder Naming
Lowercase, `snake_case` for Python packages, `kebab-case` or `camelCase` acceptable for frontend folders as long as consistent within `frontend/`. Never mix conventions within the same directory level.

### Git Commit Conventions (Conventional Commits)
Format: `<type>: <short imperative description>`
Types used in this project: `feat`, `fix`, `docs`, `chore`, `test`, `refactor`, `style`.
Examples: `feat: incident detail endpoint`, `fix: llm call robustness`, `docs: phase 3 sign-off`.
Keep the description under ~60 characters; add a longer body below a blank line if needed.

### Branch Strategy
Team-of-4 Git flow:
- `main` — always working/demoable.
- `dev` — integration branch for the current block.
- `feature/<pair>-<short-name>` — one branch per roadmap task or small cluster of tasks (e.g. `feature/pair1-ingest-endpoint`), merged into `dev` via a **PR reviewed by a teammate from the other pair**, not self-reviewed — with 4 people, real code review is possible and required before merge.
Merge `dev` → `main` at the end of each Phase/Block milestone (see Volume 2 milestones table).

### Error Handling
- Backend: raise typed exceptions (e.g. `class RuleParseError(Exception)`), catch at the API boundary, translate to proper HTTP status codes (400 for bad input, 404 not found, 422 validation, 500 only for truly unexpected errors, always logged).
- Frontend: every API call site has a try/catch (or React Query error state) and a visible user-facing error state — never a silent console-only failure.

### Logging
Structured (JSON) logs in the backend via Python's `logging` module with a JSON formatter. Log levels: `DEBUG` (dev only), `INFO` (major pipeline steps: "ingested 452 events", "3 alerts generated"), `WARNING` (recoverable issues, e.g. a malformed event skipped), `ERROR` (failed operation, includes stack trace). Never log secrets (API keys, DB credentials).

### Formatting
Python: `black` + `ruff` (or `flake8`), enforced via a pre-commit hook. TypeScript/React: `prettier` + `eslint`. Set both up in Week 4 / Week 14 respectively so formatting is never a manual chore.

---

## SECTION 8 — PROJECT MANAGEMENT ARTIFACTS

### 8.1 Sprint Plan (blocks aligned to the 30-day roadmap, Volume 2)
| Sprint | Days | Focus |
|---|---|---|
| Sprint 0 | 1–2 | Research + Planning + Design (whole team) — compressed; research itself is already captured in this handbook |
| Sprint 1 | 3–8 | Core Build A: Backend/ingestion (Pair 1) + AI/RAG foundation (Pair 2), in parallel |
| Sprint 2 | 9–14 | Core Build B: Detection + MITRE mapping (Pair 1) + RAG generation/chat with self-critique (Pair 2), in parallel |
| Sprint 3 | 15–18 | Frontend A: each pair builds UI for its own APIs, incl. source-attribution UI |
| Sprint 4 | 19–22 | Frontend B: pairs swap, polish, cross-review |
| Sprint 5 | 23–25 | Integration & Testing (whole team, mixed sub-groups) |
| Sprint 6 | 26–27 | Deployment (whole team) |
| Sprint 7 | 28–30 | Demo prep (dataset, script, two rehearsals) + final report + presentation (whole team) — expanded from 1 day, freed up by Sprint 0's compression |

### 8.2 Daily / Block Goals
Set at the start of each day from the Volume 2 table for that day and pair; roll up into a block goal at each Sprint boundary above (e.g. "Sprint 1 = backend can ingest+normalize+persist events; AI/RAG can retrieve relevant KB chunks").

### 8.3 Kanban Board (columns)
`Backlog` → `Today` → `In Progress` (WIP limit: 1 item per pair, 2 total) → `Blocked` → `In Review` (assigned to a teammate from the other pair) → `Done`. Recommended: a GitHub Projects board wired to your repo's issues, one issue per roadmap day/task, labeled by pair.

### 8.4 Risk Register
| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| LLM API costs exceed budget during testing | Low | Low | **Free-tier provider only (Gemini free tier / Groq) for the entire project — no paid API.** Cache responses during repeated testing to stay within free-tier rate limits |
| EVTX parsing library has edge-case bugs | Medium | High | Test early (Days 5–6) with 2–3 different real sample files, not one |
| Sigma rule false positive/negative rate too high | High | Medium | Build a small labeled test dataset early; measure precision/recall, don't eyeball it |
| RAG hallucination undermines credibility in demo | Medium | High | Dedicated hallucination spot-check day (Day 11); the self-critique step in the generation chain flags low-confidence claims before returning them; always show retrieved source + similarity score alongside the explanation in the UI (source attribution) |
| Scope creep (adding v2 features) | High | Medium | Volume 1 §1.8 out-of-scope list; any new idea goes to a "future work" backlog, not this sprint |
| Running out of time before deadline | Medium | High | Prioritize Phase 1/2 core over Phase 3 frontend polish, and Phase 4 testing over Phase 6 demo/report, if a block overruns (see Volume 2 "Notes on Flexibility") — Phase 6's 3 days are load-bearing for demo quality and shouldn't be the first thing cut |
| Pair coordination gaps: merge conflicts, or one pair blocked waiting on the other's hand-off (Days 11, 15, 19) | Medium | Medium | Short daily async standup near sync points (Volume 2); small, frequent PRs instead of large ones; sync points called out explicitly in the roadmap so blockers surface same-day |

### 8.5 Progress Tracker
Maintain `docs/progress.md`, updated weekly: `Phase | Days Complete | % Complete | Blockers | Notes`. This doubles as raw material for your final report's "development process" section.

### 8.6 Decision Log
Maintain `docs/decisions.md`. One entry per significant decision: `Date | Decision | Alternatives considered | Why this one | Reversible?`. Example: "Day 2 — Chose Gemini free tier over Groq/paid APIs for v1 — considered both plus paid options; chose Gemini for [reasons], stays within the free-tier-only policy — reversible, LLM client is abstracted behind `rag/llm_client.py`."

---

## SECTION 9 — DOCUMENTATION TEMPLATES

### 9.1 README.md template
```markdown
# NightOwl — AI-Powered Security Operations Center

One-paragraph description of what it does and why.

## Features
- Bullet list of core capabilities (ingestion, detection, MITRE mapping, RAG explanations, dashboard)

## Architecture
Link to docs/architecture.md + diagram

## Quick Start
\`\`\`bash
git clone <repo>
cp .env.example .env   # fill in your LLM API key
docker compose up
\`\`\`
Then open http://localhost:5173

## Tech Stack
Table: Layer | Technology

## Project Status
Current phase, link to docs/progress.md

## License
```

### 9.2 Installation Guide template
Sections: Prerequisites (Docker, Docker Compose version, an LLM API key) → Clone → Configure `.env` (table of every variable + description) → Build & run → Verify (curl a health endpoint, open the dashboard) → Common installation issues (with fixes).

### 9.3 Developer Guide template
Sections: Repo structure walkthrough → Local dev setup without Docker (running backend/frontend separately) → Running tests → Adding a new detection rule (step by step) → Adding a new API endpoint (step by step) → Code style/linting → Branching & commit conventions (link Volume 3 §7).

### 9.4 API Docs
Generate automatically via FastAPI's built-in OpenAPI/Swagger UI (`/docs`) — supplement with a short `docs/api-spec-v1.md` narrative doc explaining the overall API design philosophy and auth (if any) for v1.

### 9.5 Testing Report template
Sections: Test scope & strategy → Unit test coverage summary (with numbers) → Integration/E2E test scenarios and results → RAG accuracy evaluation methodology + results → Known issues / limitations → Conclusion (is the core journey reliable?).

### 9.6 Deployment Guide template
Sections: Requirements → Environment variables (full table) → Build steps → Run steps → Verifying a healthy deployment → Updating/redeploying → Troubleshooting (top 5 issues you actually hit during Week 17's clean-machine tests).

### 9.7 Final Report template (typical structure for a final-year project)
1. Abstract
2. Introduction (problem statement, objectives, scope) — pull from Volume 1 §1
3. Literature Review / Related Work — pull from Phase 0 competitive scan
4. System Design & Architecture — pull from Volume 1 §3, include diagrams
5. Implementation — walk through each major component (ingestion, detection, MITRE mapping, RAG, dashboard) with key code excerpts and design rationale
6. Testing & Results — pull from testing report, include RAG accuracy numbers, detection precision/recall if measured
7. Challenges & How They Were Solved — pull from decision log + risk register
8. Conclusion
9. Future Work — pull from Volume 1 §1.9
10. References
11. Appendix (full rule list, API spec, screenshots)

---

## SECTION 10 — AI MEMORY (Permanent Context — Update This Section As You Build)

> Copy-paste this section into a new AI conversation whenever you resume work, after filling in the current state.

```
PROJECT: NightOwl — AI-Powered SOC
CURRENT PHASE: [Phase 0 / 1 / 2 / 3 / 4 / 5 / 6]
CURRENT DAY (of 30): [n]
PAIR(S) ACTIVE TODAY: [Pair 1 / Pair 2 / both]

WHAT'S ALREADY BUILT:
- [list, e.g. "EVTX ingestion for event IDs 1,3,11", "12 Sigma rules", "incident grouping v1"] — note which pair built each item

COMPLETED TASKS (recent):
- [last 3-5 roadmap days completed]

PENDING TASKS (next):
- [next 3-5 roadmap days]

CURRENT ARCHITECTURE:
- [confirm still matches Volume 1 §3, or note deltas]

CURRENT FOLDER STRUCTURE:
- [confirm still matches Volume 1 §3.3, or note deltas]

CURRENT API ENDPOINTS:
- [list method + path + one-line purpose]

CURRENT DATABASE SCHEMA:
- [table names + key columns, or link to docs/schema-v1.md]

CURRENT KNOWN BUGS / LIMITATIONS:
- [list]

CURRENT PRIORITIES:
- [1-3 things being worked on right now]

FUTURE ROADMAP (unchanged reference):
- See Volume 2 for full day-by-day plan; Volume 1 §1.9 for post-v1 future scope.
```

---

## SECTION 11 — HOW TO INTRODUCE NEW CONCEPTS (for the AI assistant)

Whenever a new concept comes up during development (e.g. "what is a Sigma rule condition block", "what is cosine similarity in vector search"), explain it in this order:
1. **Beginner explanation** — plain language, no jargon.
2. **Real-world analogy** — something familiar.
3. **Technical explanation** — the precise, correct version.
4. **Why NightOwl needs it** — tie back to this specific project.
5. **How we will implement it** — concrete next step.
6. **Common mistakes** — what beginners typically get wrong.

Example (cosine similarity):
1. It's a way to measure how "similar in meaning" two pieces of text are.
2. Like comparing two arrows by the angle between them — pointing the same direction means similar, even if one arrow is longer.
3. Formally: the cosine of the angle between two vectors in embedding space; ranges -1 to 1, closer to 1 = more similar.
4. NightOwl uses it to find which MITRE technique docs/playbooks are most relevant to a given incident's context.
5. ChromaDB computes this automatically when you call its query function with an embedded query vector.
6. Common mistake: assuming a high similarity score means factually correct — it means *topically similar*, not *true*. Always sanity-check retrieved content.

---

## SECTION 12 — FINAL CHECKLISTS

### Daily Checklist
- [ ] Today's roadmap task is complete (or explicitly rolled to tomorrow)
- [ ] Code runs / builds without errors
- [ ] Change committed with a conventional commit message
- [ ] One sentence written on what was learned

### Weekly Checklist
- [ ] All days in the week completed or consciously rolled forward
- [ ] `docs/progress.md` updated
- [ ] Anything confusing added to a "revisit" list
- [ ] Code formatted/linted, no lingering TODOs without a tracked issue

### Monthly Checklist
- [ ] Milestone for the phase(s) completed this month hit (see Volume 2 milestones table)
- [ ] Decision log updated with any major choices made
- [ ] Risk register reviewed — any new risks surfaced?
- [ ] Demo the current state to someone (mentor, friend) for outside feedback

### Project Completion Checklist
- [ ] All 8 phases signed off (Volume 2 phase summary docs exist)
- [ ] Core user journey works reliably (upload → incidents → explanation → chat)
- [ ] `docker compose up` works from a clean clone
- [ ] Final report complete and proofread
- [ ] Presentation slides complete
- [ ] Demo rehearsed at least twice

### Deployment Checklist
- [ ] `.env.example` documents every required variable
- [ ] No secrets committed to Git (check with `git log -p | grep -i api_key` style audit)
- [ ] Health check endpoints work
- [ ] Tested on a genuinely clean machine/VM, not just your dev machine

### Documentation Checklist
- [ ] README complete and accurate
- [ ] Installation guide tested by following it literally, step by step
- [ ] API docs (Swagger) accessible and accurate
- [ ] Deployment guide tested
- [ ] Final report complete

### Presentation Checklist
- [ ] Demo script written (what you'll show, in what order, ~10-15 min)
- [ ] Backup plan if live demo fails (recorded video/screenshots)
- [ ] Slides cover: problem, architecture, live demo, results/metrics, future work
- [ ] Rehearsed at least twice, timed
- [ ] Anticipate 3-5 likely viva questions and prepare answers (e.g. "why rule-based detection instead of ML?", "how do you prevent RAG hallucination?", "how does this differ from existing SIEM tools?")
```
