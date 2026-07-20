# NightOwl Engineering Handbook — Volume 4
## Live Development Memory & Working Templates

This volume is the "living" companion to Volumes 1–3. Those set the plan once; this one gets edited constantly — every session, every day, every decision. Keep this file open (or pasted into your AI chat) every time you sit down to work on NightOwl.

**How to use this volume:**
- Section 1 (Live Development Memory) — update at the **end of every session**. It's the single source of truth for "where am I right now."
- Section 2 (AI Session Prompt) — paste at the **start of every session**, with Section 1 filled in underneath it....
- Sections 3–5 (Journal, ADR, Bug Tracker) — copy the template into a new dated entry whenever the situation applies (daily / on a design decision / on a bug).
- Section 6 (AI Conversation Rules) — permanent, rarely edited, referenced by every AI assistant automatically.

---

## SECTION 1 — LIVE DEVELOPMENT MEMORY

> This is a **template**. Keep one live copy at `docs/memory/live-memory.md` in your repo and overwrite it each session — don't append forever, or it becomes useless. Git history preserves old versions if you ever need to look back.

```markdown
# NightOwl — Live Development Memory
Last updated: [YYYY-MM-DD]

## Current Phase
[Phase 0 Research / Phase 1 Planning / Phase 2 Design / Phase 3 Backend /
 Phase 4 AI / Phase 5 Frontend / Phase 6 Testing / Phase 7 Deployment / Phase 8 Final]

## Current Day
Day [n] of 126 (see Volume 2 roadmap)

## Completed Features
- [Feature] — done on Day [n]
- [Feature] — done on Day [n]
- (Keep this list to real, working, tested features — not "started")

## Pending Features
- [Feature] — planned for Day [n]
- [Feature] — planned for Day [n]

## Current Folder Structure
```
[paste `tree -L 3` output of backend/ and frontend/, or note
 "unchanged from Volume 1 §3.3" if nothing has drifted]
```

## Current API Endpoints
| Method | Path | Purpose | Status |
|---|---|---|---|
| GET | /health | health check | ✅ working |
| POST | /ingest | upload + process EVTX | ✅ working |
| GET | /incidents | list incidents | 🚧 in progress |
| ... | ... | ... | ... |

## Current Database Schema
[Link to docs/schema-v1.md, or paste a short table list with
 1-line description each if the schema has drifted from the original plan]

## Current Bugs
| Bug ID | Description | Severity | Status |
|---|---|---|---|
| BUG-012 | EVTX parser crashes on empty file | High | Open |
| BUG-013 | ... | ... | ... |
(Full detail lives in Section 5 Bug Tracker — this is just the open-issues summary)

## Current Priorities
1. [Most important thing right now]
2. [Second priority]
3. [Third priority]

## Next Immediate Task
[The literal next thing to do when this session starts —
 specific enough that you could hand it to someone else.
 E.g. "Implement incident grouping logic in services/incident_service.py
 per Volume 2 Day 35 — group alerts by same host + 10-minute window."]

## Recently Completed Work (last 3–5 sessions)
- Day [n]: [what was done]
- Day [n]: [what was done]
- Day [n]: [what was done]

## Future Improvements (not urgent, don't lose track of these)
- [idea]
- [idea]

## AI Context Summary
[3-5 sentence plain-English summary an AI assistant can read in 10 seconds
 to understand exactly where the project stands. Example:
 "NightOwl's backend can ingest EVTX files, normalize events, and run them
 against 12 Sigma rules, persisting alerts to Postgres. Incident grouping
 and MITRE mapping are not yet implemented — that's the current focus.
 No frontend or RAG work has started yet. Architecture and folder structure
 match Volume 1 exactly, no deviations so far."]
```

### Resume Template — After a Long Break

Use this when you haven't touched the project in more than ~1 week. Fill it in, paste it into a fresh AI conversation along with the current Live Development Memory above, and the AI Session Prompt (Section 2).

```markdown
# NightOwl — Resume After Break

Break length: [e.g. 3 weeks]
Last touched: [date]
Last known-good state: [e.g. "backend detection engine passing tests,
 frontend not started"]

Before we continue, please:
1. Read the Live Development Memory above and summarize the project
   state back to me in 5 sentences, so I can confirm it's accurate.
2. Ask me to confirm or correct anything that seems out of date.
3. Re-check: does `docker compose up` (or my documented local dev
   setup) still work? Walk me through verifying this before we
   write any new code.
4. Once confirmed, tell me the single next task from the roadmap
   (Volume 2) and briefly remind me why it matters, before we start.

Do NOT start writing new code until step 3 (environment verification)
is confirmed working.
```

---

## SECTION 2 — AI SESSION PROMPT TEMPLATE

> Paste this at the very start of every coding session, followed by your current **Live Development Memory** (Section 1). This re-establishes how the AI should behave every single time, regardless of which AI tool you're using.

```markdown
You are acting as my Senior Software Engineer and Mentor on my solo,
AI-assisted final-year project: NightOwl, an AI-Powered Security
Operations Center. I am a student learning while building — explain
things, don't just generate code at me.

Before you do anything else:
1. Read the "Live Development Memory" I've pasted below this prompt.
   It tells you the current phase, day, completed/pending features,
   architecture, API, schema, bugs, and priorities.
2. Confirm your understanding of where the project currently stands
   in 2-3 sentences before proceeding.
3. Confirm what today's task is (from the roadmap or from what I
   tell you), and briefly explain why that task matters at this
   stage — don't skip straight to code.

Rules for this session:
- Explain BEFORE you code: what we're building, why this approach,
  what tradeoffs exist versus at least one alternative.
- Follow the roadmap (Volume 2) and architecture (Volume 1) exactly.
  If you think a deviation is justified, STOP and explain the
  tradeoff — do not silently change direction.
- Never over-engineer. No frameworks, abstractions, services, or
  infrastructure beyond what this specific task needs. This is a
  solo 120-day student project, not an enterprise system.
- Generate modular code: small, single-responsibility files and
  functions, following the folder structure in Volume 1 §3.3 and
  the coding standards in Volume 3 §7.
- After generating any file, explain what it does, line-by-line for
  anything non-obvious, and why it's structured this way.
- Suggest what should be tested for anything you generate, and
  ideally provide the test.
- If a change would affect the architecture, database schema, or
  API contract in a way not already planned in Volumes 1-2, STOP and
  explain the proposed change and its impact before writing code.
  Wait for my explicit confirmation.
- If I ask for something outside the current phase's scope, flag it
  as a scope change and ask whether I want to log it as "future
  work" (Volume 1 §1.9) or actually pull it into scope now.
- Keep files under ~250 lines where reasonably possible; propose a
  split if a file is growing past that.
- When introducing a new concept (cybersecurity or technical), use
  the beginner-explanation order from Volume 3 §11: beginner
  explanation → analogy → technical explanation → why NightOwl
  needs it → how we'll implement it → common mistakes.

At the end of this session, help me update the Live Development
Memory (Section 1 of Volume 4) with what changed, so the next
session can pick up cleanly.

--- PASTE LIVE DEVELOPMENT MEMORY BELOW THIS LINE ---
```

---

## SECTION 3 — DAILY DEVELOPER JOURNAL TEMPLATE

> Create one entry per working day at `docs/journal/YYYY-MM-DD.md`. Takes 5 minutes at the end of a session; pays for itself the moment you need to remember why you made a decision, or when writing the final report.

```markdown
# Developer Journal — [YYYY-MM-DD]

## Date
[YYYY-MM-DD]

## Phase
[Phase name, from Volume 1 §4]

## Day Number
Day [n] of 126

## Goal
[Today's roadmap goal, copied from Volume 2]

## Work Completed
- [what actually got done — be honest, partial progress counts]
- [...]

## Problems Faced
- [problem 1 — be specific: error message, unexpected behavior, confusing concept]
- [problem 2]

## Solutions
- [how problem 1 was resolved, or "unresolved — carried to tomorrow"]
- [how problem 2 was resolved]

## Lessons Learned
[1-3 sentences — what do you understand now that you didn't this morning?
 This is the single most valuable field for your final report's
 "development process" and "challenges" sections.]

## Git Commit
`[commit hash or message, e.g. "feat: incident grouping v1 (a3f21c9)"]`

## Next Day Plan
[Specific next task — pull from Volume 2, adjust if today ran long/short]

## Questions for AI
- [anything you didn't fully understand today, to ask at the start
  of tomorrow's session — don't let confusion silently accumulate]
```

---

## SECTION 4 — ARCHITECTURE DECISION RECORD (ADR) TEMPLATE

> One ADR per significant, hard-to-reverse decision — new dependency, schema change, choice between two real alternatives, anything you'd want to defend in a viva. Store at `docs/adr/NNN-short-title.md`, numbered sequentially. Not every decision needs one — daily small choices go in the Decision Log (Volume 3 §8.6); ADRs are for the ones with lasting architectural weight.

```markdown
# ADR-[NNN]: [Decision Title]

## Date
[YYYY-MM-DD]

## Status
[Proposed / Accepted / Superseded by ADR-XXX]

## Problem
[What decision needed to be made, and why now? What constraint or
 requirement triggered this?]

## Options Considered
### Option A: [name]
[Brief description]

### Option B: [name]
[Brief description]

### Option C: [name] (if applicable)
[Brief description]

## Selected Option
[Which one, stated plainly]

## Why It Was Chosen
[The actual reasoning — tie back to project constraints: solo dev,
 120-day timeline, learning goals, resource limits, viva
 defensibility, etc.]

## Pros
- [pro 1]
- [pro 2]

## Cons
- [con 1 — be honest about the real tradeoff, not just "none"]
- [con 2]

## Future Impact
[What does this decision constrain or enable later? Would reversing
 this be easy, hard, or practically impossible at this point? Note
 any related "future work" item this creates.]
```

**Example (filled in) — for calibration:**

```markdown
# ADR-003: Rule-Based Detection Instead of ML-Based Anomaly Detection

## Date
2026-07-20

## Status
Accepted

## Problem
Detection needs a method to flag suspicious events from normalized
Sysmon data. Two broad approaches exist: rule-based (Sigma) or
ML-based anomaly detection.

## Options Considered
### Option A: Sigma rule-based detection
Human-authored YAML rules matched against normalized events.

### Option B: ML-based anomaly detection
Train a model (e.g. isolation forest) on "normal" behavior, flag
deviations.

## Selected Option
Option A — Sigma rule-based detection.

## Why It Was Chosen
Rule-based detection is explainable (a requirement, since the RAG
layer needs to explain WHY something was flagged), doesn't require
a labeled training dataset I don't have, is the industry-standard
approach in real SOC tooling (defensible in a viva), and fits a
120-day solo timeline without a separate ML research/training track.

## Pros
- Explainable by construction — traces directly to a MITRE technique
- No training data or model tuning needed
- Matches industry practice (Sigma is a real, widely used standard)
- Faster to implement and test within the timeline

## Cons
- Can't detect genuinely novel attack patterns with no matching rule
- Rule quality directly limits detection quality — false
  negatives are a real risk if rule coverage is thin

## Future Impact
Documented as a v1 limitation (Volume 1 §1.8) with ML-based
anomaly detection explicitly listed as future work (§1.9). Fully
reversible/extensible later — an ML layer could sit alongside the
rule engine as an additional signal without replacing it.
```

---

## SECTION 5 — BUG TRACKER TEMPLATE

> Maintain at `docs/bugs/bug-tracker.md` as one running table (or one file per bug under `docs/bugs/BUG-NNN.md` if a bug needs a long writeup). The table format below is enough for most entries.

```markdown
# NightOwl — Bug Tracker

| Bug ID | Description | Severity | Root Cause | Fix | Status | Date Fixed |
|---|---|---|---|---|---|---|
| BUG-001 | EVTX parser crashes on empty file | High | No guard for zero-length files before parsing | Added file-size check + explicit 400 error response | Fixed | 2026-07-22 |
| BUG-002 | Severity score identical for all incidents | Medium | Weighting formula bug — tactic weight always defaulted to 1 | Fixed default lookup in severity_service.py | Fixed | 2026-07-25 |
| BUG-003 | Chat responses ignore incident context after 2nd message | High | Retrieval only scoped to first message, not full thread | Rewrote retrieval to include running chat history | Open | — |
```

**Field definitions:**
- **Bug ID** — sequential, `BUG-001`, `BUG-002`, ... never reused.
- **Description** — one line, specific enough to search for later.
- **Severity** — `Critical` (breaks core journey) / `High` (breaks a feature) / `Medium` (degraded but usable) / `Low` (cosmetic/edge case).
- **Root Cause** — the actual underlying reason, not just the symptom. If unknown yet, write "Investigating."
- **Fix** — what was changed to resolve it. Link a commit hash if useful.
- **Status** — `Open` / `In Progress` / `Fixed` / `Won't Fix` (with a one-line reason if so).
- **Date Fixed** — leave blank (`—`) until resolved.

**Individual bug write-up template** (for anything complex enough to need more than the table row):

```markdown
# BUG-[NNN]: [Short Title]

**Severity:** [Critical / High / Medium / Low]
**Status:** [Open / In Progress / Fixed / Won't Fix]
**Found on:** [Day n, YYYY-MM-DD]
**Fixed on:** [Day n, YYYY-MM-DD, or "—"]

## Description
[What happens, and how to reproduce it]

## Root Cause
[The actual underlying reason]

## Fix
[What was changed — link commit]

## Prevention
[Anything added to prevent this class of bug recurring —
 e.g. a new test case, a validation added, a lint rule]
```

---

## SECTION 6 — AI CONVERSATION RULES (Permanent)

> These are permanent, project-wide rules every AI assistant (Claude, ChatGPT, Gemini, Cursor, Codex, Windsurf) must follow on NightOwl, regardless of session or phase. They don't change week to week — reference them, don't rewrite them.

### Behavior Rules
1. **Never change architecture without explanation.** Any deviation from Volume 1's architecture must be explicitly proposed, with tradeoffs, before code is written.
2. **Never generate code without explaining why.** Every non-trivial code suggestion is preceded by: what it does, why this approach, and what alternative was considered.
3. **Prefer modular code.** Small, single-responsibility files and functions over large, multi-purpose ones.
4. **Keep files under ~250 lines where possible.** If a file is growing past that, propose a split before it happens, not after.
5. **Follow SOLID principles**, especially single-responsibility and dependency inversion (services depend on abstractions/interfaces where it meaningfully helps testability — not gratuitously).
6. **Explain cybersecurity concepts with beginner examples first.** Use the order from Volume 3 §11: beginner explanation → analogy → technical explanation → why NightOwl needs it → implementation → common mistakes. Never assume prior security knowledge.
7. **Stay within project scope.** Anything not in Volume 1 §1.7 (in-scope) is either declined or explicitly flagged as a scope change requiring confirmation — never silently added.
8. **Suggest industry best practices**, and say when NightOwl intentionally deviates from them for timeline/scope reasons (and note the tradeoff).
9. **Wait for confirmation before major architectural changes** — database schema changes, new major dependencies, API contract-breaking changes, or anything that would invalidate an existing ADR.
10. **Always suggest what should be tested** for any non-trivial code generated, and offer to write the test.
11. **Read and respect the Live Development Memory (Volume 4 §1)** at the start of every session — don't propose work that duplicates what's already built, or that ignores currently known bugs.
12. **Never fabricate project state.** If context is missing or ambiguous (e.g. unclear what's actually implemented), ask rather than assume.
13. **Respect the roadmap's sequencing.** Don't suggest jumping ahead to a later phase's work (e.g. frontend polish) while an earlier phase's core deliverable (e.g. detection accuracy) is still unresolved, without flagging that tradeoff explicitly.
14. **Keep the developer's learning goal central.** This is a learning-while-building project — a working shortcut that the developer doesn't understand is worth less than a slightly slower path they do understand. When in doubt, explain more, not less.

### Quick-Reference Checklist (for the AI to self-check before responding)
- [ ] Did I explain *why* before *how*?
- [ ] Is this code modular and within scope?
- [ ] Did I flag any architecture/schema/API impact?
- [ ] Did I suggest a test?
- [ ] Did I check this against the Live Development Memory?
- [ ] Am I about to over-engineer? If yes, stop and simplify.
