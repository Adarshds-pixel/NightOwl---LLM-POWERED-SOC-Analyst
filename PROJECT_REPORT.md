# NightOwl — Complete Project Report

Everything about the project in one file: what it is, what you decided, what was built and why, what was measured, where it stands today, and what is left for you to do.

> **Snapshot:** 8 October 2026 · branch `fix/production-readiness` (21 commits, **not pushed**) · 788 backend tests passing · detection **59/61** with the correct ATT&CK technique and **0** false alarms on the benign corpus · all **41** benign sample files read **Normal**.
>
> This file is the story and the status. For deep technical reference (API tables, data model, environment variables, troubleshooting) see `docs/DOCUMENTATION.md`; for the machine-learning layer see `ML.md`; for the quick start see `README.md`.

---

## 1. What NightOwl is

NightOwl turns Windows event-log exports (EVTX files: Sysmon, Security, PowerShell, System, Application) into a small number of prioritised, explained incidents.

- **Detects** known malicious behaviour with Sigma-style YAML rules and multi-event "sequence" detectors, and maps each finding to MITRE ATT&CK.
- **Groups** detections into incidents per host and time, with severity, a status workflow and an audit trail.
- **Explains** each incident in plain English with a retrieval-grounded LLM (ChromaDB knowledge base + Groq), including sources and a self-check pass, and answers follow-up questions in an incident chat.
- **Reviews** the events no rule checks with an advisory AI review, clearly labelled as not a detection.
- **Records** statistically unusual windows of activity with an experimental ML layer, kept strictly separate from detections.
- **Shows** all of it in a React SOC console behind a single-admin login.

It is not "a SOC platform that detects every attack". It is an evidence-driven investigation tool that says what it checked, what it did not, and what it cannot tell.

**Team and method:** a 4-person final-year project, built AI-assisted. Free-tier only: Groq for the LLM; everything else is open source and self-hosted.

---

## 2. Objectives and outcomes

| # | Objective | Outcome |
|---|---|---|
| 1 | Understand the whole project and report every bug, gap and false claim | Done: a full audit of backend, detection, ML, frontend and docs. |
| 2 | Keep a restore point before changes | Done: branch `backup/pre-ml` (`e6a9066`) and tag `pre-latest-pull` (`b5e8d1f`), both pushed to GitHub. |
| 3 | Fix every bug and gap; make it production and demo ready | Done in code, committed locally. Verified by tests, a Docker install and a headless-browser run (see §8). |
| 4 | Correct the ML features | Rebuilt and evaluated honestly. It ships in **advisory mode** because it needs more benign data (see §9). |
| 5 | Benign files must read **Normal**, never "Suspicious" or "Inconclusive" | Done: **41 of 41** benign sample files read Normal. (An earlier count of 42 wrongly included a malicious capture; see §6.) |
| 6 | Make the AI second opinion consistent with the verdict | Done: it only reviews events no rule checks, says so on screen, and has a Retry button. |
| 7 | Catch the attacks the rules missed | 5 more caught; 3 remain (see §8). |
| 8 | Honest, measured numbers everywhere | Done: every figure comes from a script in `backend/scripts/`. |
| 9 | Never push without permission; test end-to-end and visually first | Followed. Nothing is pushed. |
| 10 | Make the ML layer accurate enough to raise alerts | **Not done — needs your benign logs.** |

---

## 3. History: from the start to now

### 3.1 Before this work (the original build)

- Built over a 30-day roadmap by two rotating pairs across backend, AI/RAG and frontend.
- Detection accuracy grew with the corpus, each step measured: **3/32 → 18/32 → 24/32 → 26/39 → 31/39 → 33/39 → 47/54 → 50/61** (at the time scored as "any matching alert", with 45 rules and 3 sequence patterns).
- Notable early decisions: Groq-only LLM (Gemini removed after its free tier proved unreliable); pySigma for rule validation with NightOwl's own evaluator; one admin account; Demo Mode built from real captures; a live-replay demo was built and then removed.
- An ML anomaly layer was added late. It reported 97.8% accuracy, measured on its own training data.

### 3.2 This engagement (October 2026)

**Step 1 — Audit and backup.** You asked for a full analysis. Findings: a fail-open auth default, a broken frontend build, false-positive-prone rules, a train/serve mismatch in the ML layer, many misleading UI claims and false documentation claims. You chose to back up **both** locally and on GitHub; that was done before any change.

**Step 2 — Production-readiness work (7 phases, 11 commits).**

| Phase | Commit | What changed |
|---|---|---|
| 1 Security and deploy | `667c8e0` | Fail-closed session secret; server-side revocable sessions; CSRF header; pre-body upload guard; pinned dependencies; one-command Docker stack; broken frontend build fixed |
| 2 Backend correctness | `1273e28` | UTC timestamps; exact channel matching; nested EventData; sliding incident grouping; alert de-duplication; per-host ingest lock; evidence-keyed caches; vendored ATT&CK data; migration fixes |
| 3 AI/RAG | `508452c` | Log text fenced in prompts; strict verdict parsing; invented ATT&CK ids flagged; parent-technique retrieval; `/system/status` |
| 4 Detection | `dcc2029` | Strict rule loading; Sigma subset widened; 14 new rules + 5 sequence detectors; false-positive fixes; honest benchmark: 52/60, 5 false positives |
| 5 ML | `12b44f2` | Rebuilt per log family on upload-shaped windows; minimum window size; per-feature explanations; advisory mode |
| 6 Frontend | `241a53d` | ML kept separate from detections; real status badges; race, pagination, sort and overlay fixes; honest copy |
| 7 Docs and deploy | `d12aff4`, `92c102f` | Docs rewritten from measured results; Postman rebuilt; Docker fixes (CPU-only torch, quoted password hash) |

**Step 3 — Browser test with real files** (`849931d`, `7403826`, `cdd3601`). A walkthrough on a clean Docker install found and fixed: Security events carrying no account or process, the audit actor logged as "system", the AI quoting a wrong year, raw Markdown in AI text, and display glitches. The deployment bugs above were found here.

**Step 4 — The upload audit.** You reported that benign files showed "No rule coverage", "Inconclusive" or "Suspicious". We reset the data and uploaded **all 102 sample files** one by one. Result: only 2 of 34 benign files read correctly, the AI hedged on routine events, and 7 attack captures were missed or flagged for the wrong reason. Report: https://claude.ai/artifact/MKcLhZXb9hHao6sNYebhMR (private link; includes an "After the fixes" section).

**Step 5 — Fixing what the audit found** (`48ee98b`, `53f07de`, `edfd521`). Details in §4.4; results in §8.

**Step 6 — Headless-browser verification.** The Chrome extension would not connect, so a headless Chrome drove an isolated copy of the app and I read the screenshots.

---

## 4. How it works (implementation)

### 4.1 Pipeline

```
EVTX upload (one file = one channel)
  → read & normalise (UTC time, channel, fields incl. UserData)       → events
  → detect: 66 Sigma-style rules per event + 10 sequence detectors     → alerts
  → classify every event type: checked / everyday / unchecked
  → correlate: sliding 1-hour window per host                         → incidents
  → ML anomaly layer (advisory): unusual 10-minute windows            → alerts (kind=ml)
  → AI review of unchecked events (advisory)
  → console: verdict, telemetry profile, incidents, explain, chat
```

### 4.2 Detection

- **Rules:** 66 YAML files in `backend/app/detection/rules/`. A rule is rejected at load time if it uses an unsupported modifier, an unparseable condition, an unscoped category, or an ATT&CK tactic tag that does not belong to its technique (ATT&CK v19.2, bundled offline).
- **Supported Sigma subset:** named selections; `contains`, `startswith`, `endswith`, `re`, `cidr`, `all`, `windash`, wildcards, null; `and/or/not`, parentheses, `1 of` / `all of`. No `eval()`.
- **Sequence detectors (10):** Process Herpaderping, SMB share-enumeration probe, Kerberos password spray, authentication brute force, remote SAM/LSA enumeration, mass process access, group self-add, bulk group addition, and two new ones: **SMB fan-out** (one process opening port-445 connections to 5 or more hosts within 60 s) and **named-pipe sweep** (one process connecting to 8 or more distinct RPC pipes within 5 s).
- **Severity:** Sigma level plus a +1 for high-leverage tactics. **Alert de-duplication:** the same rule, host and process within 60 s folds into one alert with a count. **Incidents:** open or investigating, same host, sliding 1-hour window, title follows the most severe alert.

### 4.3 Coverage and verdicts (the core of the benign-file fix)

Every event type (channel + event id) is sorted in `backend/app/detection/coverage.py`:

| Kind | Meaning | Example |
|---|---|---|
| **Checked** | A rule, a sequence detector or the notice generator evaluates it | Sysmon 1, Security 4625, System 7045 |
| **Everyday** | Routine activity no attack rule needs | Security 5379 credential-manager reads, Sysmon 5 process exits, System/Application operational events |
| **Unchecked** | Security-relevant or unknown, and nothing evaluates it | Security 5136, Sysmon 22, unknown channels |

Verdict (`frontend/src/lib/verdict.ts`, mirrored in `backend/scripts/upload_sweep.py`): a detection → **Suspicious activity detected**; no detection but unchecked events or an advisory pattern → **Review recommended**; otherwise → **Normal — no threats detected**. The AI second opinion never changes the verdict.

Two bugs were behind the old behaviour: any event type without a rule counted as "no coverage", and rules scoped by an explicit `EventID` plus the sequence detectors were not counted as coverage at all.

### 4.4 What the October audit fixed

- **Everyday vs unchecked** classification (above), with each everyday entry carrying its reason.
- **Log clears:** System 104 is now an informational **notice** naming the account and log, read from the event's `UserData` (which used to be dropped). It opens no alert. Security 1102, the clear attackers use, stays a detection.
- **Raw ETW RPC records** (PetitPotam) get their own `rpc` channel; a new rule detects the EFSRPC call.
- **Eight new rules:** browser-initiated Windows logon check; two UAC-bypass signals (OskSupport.dll outside Windows, accessibility binary run from outside Windows); WMI-spawned process (Sysmon and Security 4688); account modified by another user; EFSRPC call; and (added after the undetected-files check) a BITS job created by a process that never uses BITS. Each was checked against all 40 benign captures: zero hits.
- **AI review:** reads only unchecked events and advisory-pattern events (benign files make **no** AI call); the panel is titled "AI review of unchecked events" and says the rule detections are listed above; up to 8 sampled events; a failed review can be retried (`POST /ai-opinions/{id}/retry`).
- **Large uploads:** `POST /ingest/async` returns a job id at once, `GET /ingest/jobs/{id}` reports progress, and the console shows "Reading… N records". The upload size guard now covers the async route too.
- **ML visibility:** a Settings → "ML model" panel (`GET /ml/model`), an ML line on every upload's profile, and a repeatable visual check in `ML.md`.
- **Demo Mode:** fixtures over 2 MB are never offered (a demo click must finish in seconds); five newly detected captures moved to `detected/`.

### 4.5 AI layer

Retrieve → draft → self-critique. ChromaDB holds 1,888 chunks (ATT&CK techniques + five playbooks), embedded with `all-MiniLM-L6-v2`. Untrusted log text is fenced with a random per-request nonce; model-invented ATT&CK ids are annotated as unverified; chat is one call per turn and is stored only after the model answers. Groq only (`openai/gpt-oss-120b`), no silent fallback; a free-tier limit shows as a clear 503 and, for the opinion, a Retry button.

### 4.6 ML layer (advisory)

Per log family (Security, Sysmon, System, Application; PowerShell skipped) a Ledoit-Wolf Mahalanobis model over `log1p` features of 10-minute windows, scored on the same window shape an upload produces; windows under 10 events are never scored. Each record stores its distance, thresholds, window, the features that drove it and any never-seen event types. Mode `ML_MODE`: `advisory` (default), `alert`, `off`.

Measured on held-out benign data: about **1.3–4.5 false windows per machine per day** on a familiar machine, and it **does not transfer** to unseen machines. In the browser run, benign files still produced ML records (2 on `system_baseline`, 2 on `security_window_07`). On the sample attack captures its flags are driven mostly by what is *missing* (no process-exit events), not by attack content. Hence advisory only. Full detail in `ML.md`.

### 4.7 Security and deployment

- **Auth:** one admin (bcrypt hash); signed HttpOnly cookie backed by a revocable server-side session; failed-login throttle; identical responses for wrong user and wrong password; passwords over 72 bytes handled.
- **Request protection:** CSRF header on every state-changing request; pre-body upload guard (`/ingest`, `/ingest/async`); per-IP rate limit; CSV-injection guard; `/docs` hidden outside local.
- **Startup checks:** outside `APP_ENV=local` the backend refuses to start without a 32+ character session secret and an admin hash.
- **Docker:** `docker compose up --build` runs migrations, builds the knowledge base on first start (about 3 minutes, needs network once), serves the console through nginx with security headers, binds the database to loopback, uses CPU-only torch. **The bcrypt hash in `.env` must be in single quotes** or Compose corrupts it.
- **Frontend:** React 19, Vite, Tailwind v4, no secrets in the bundle.

### 4.8 Where things live

```
backend/app/detection/   rules/, engine.py, sequences.py, coverage.py
backend/app/ingestion/   evtx_reader.py, normalizer.py
backend/app/services/    ingest_service.py, ingest_jobs.py, incident_service.py, ai_opinion_service.py
backend/app/api/         routes_*.py (ingest, incidents, events, alerts, rules, ml, system, ...)
backend/app/ml/          detector.py, features.py, windows.py, runtime.py, models/
backend/app/rag/         explain/chat services, prompts, safety, retriever
backend/scripts/         run_detection_benchmark.py, build_failure_matrix.py, upload_sweep.py,
                         train_ml_model.py, eval_ml_model.py, collect_benign_logs.ps1
backend/sample_logs/     real_world_fixtures/{detected,undetected,NightOwl-Benign-Dataset,benign}
frontend/src/            pages, components, hooks, lib (verdict.ts), api
docs/                    DOCUMENTATION.md, postman/
```

---

## 5. Decisions you made

| Decision | Why / effect |
|---|---|
| Back up before changing anything, locally **and** on GitHub | `backup/pre-ml`, tag `pre-latest-pull`. Done. |
| Work on a separate branch `fix/production-readiness` | Nothing touched `main`. |
| **Never push without your permission**; always run visual and end-to-end tests first | Followed throughout; nothing is pushed. Saved to memory. |
| Single-line commit messages, no co-author trailer | Followed. |
| Get approval before live Sysmon or tool-config changes; don't build ahead of the roadmap | Followed. |
| Benign files must read Normal, never Suspicious, Inconclusive or "no coverage" | Drove the coverage redesign. |
| Test by uploading **every** sample file yourself in Chrome, after resetting the data | Done: 102 files, plus the report. |
| You will collect benign logs from more machines for the ML layer | **Still to do (§9).** |
| Keep the project honest: no invented numbers, panels or accuracy claims | Every figure is script-generated; unsupported panels were removed. |

Decisions that were made along the way and still stand (technical):

- **Groq only**, no silent fallback. **Single admin**, no roles. **Strict rule loading.** **Vendored ATT&CK data.** **ML demoted to advisory** after the first version's 97.8% was found to be measured on its own training data.
- **System-log clears are a notice, Security-log clears stay a detection** (agreed during planning, in line with your "benign must not look suspicious" rule).
- **Routine-vs-unchecked is judged from measured benign data**, and `PowerShell 4103` is classed as everyday on the reasoning that script text is judged from 4104 (a deliberate trade-off).
- **The Rust EVTX parser was not adopted:** it is 10–25× faster on Linux but its output differs from the current parser (GUID case, logon-id format, legacy fields), and its package name collides with the current parser on Windows.

---

## 6. Measured results (all script-generated)

| What | Result | Script |
|---|---|---|
| Attack captures with the **correct ATT&CK technique** | **59 / 61** (was 52 / 60) | `run_detection_benchmark.py` |
| Attack captures raising any alert | 60 / 61 | same |
| False alarms on 39 benign captures (315,337 events) | **0** (was 5) | same |
| Verdict for each of the 102 sample files | 41 benign → **Normal**; 60 attack → Suspicious; 1 → Review recommended | `upload_sweep.py` |
| Backend tests | 778 offline + 5 integration | `pytest` |
| ML false windows per machine per day (held-out benign) | 1.3 – 4.5 | `eval_ml_model.py` |

**Caveats:** every attack capture informed rule development, so these are development-set figures. The everyday-event lists were measured on the same benign corpus: a new machine can still read "Review recommended" until its everyday events are added. Your new benign logs are the real held-out test.

**Still not caught as an attack (2):** a UserHunter capture that holds a single `System` -> `\srvsvc` pipe event (identical to an ordinary share browse; it reads **Review recommended**) and the NTLM self-relay capture (flagged for its WMI execution and a log clear, but the relay itself is not visible: the logons are Kerberos).

**A mistake found and fixed on 8 October:** `bits_openvpn.evtx` had been written off as a mislabelled benign capture. Reading its events showed a 32-bit `notepad.exe` creating BITS jobs with random names that download `https://i.imgur.com/IFpvPlt.png` every few minutes (BITS-based command-and-control). The coverage change had also classed the whole BITS log as everyday, so it read Normal. BITS is no longer everyday, a rule flags BITS jobs created by processes that never use BITS, the ground truth is corrected, and the benign count is 41, not 42.

---

## 7. Current status

**Done, committed locally (not pushed):** everything in §3–§4. Working tree is clean at `edfd521`.

**Verified**

- 788 backend tests pass; frontend type-check and build pass; lint shows warnings only.
- Clean Docker install in production mode: migrations, knowledge-base build, login, Demo Mode, upload, incident, explain, chat, status change and audit, logout and session revocation.
- The new routes and rules running **inside the production backend image** against a throwaway database.
- A headless Chrome run on an isolated copy: Normal verdicts on benign files, log-clear notices with the account, Suspicious on attacks, the ML panel, the ML alerts view, the new Logs cards.
- The full 102-file sweep and the benchmark.

**Not verified yet — be aware**

- The Chrome **extension** never connected, so I had no live control of your own browser. The headless run covered the main screens, but **the AI Retry button, Demo Mode after these changes, and the 56 MB upload through the new async path have not been exercised in a browser.** Please try them (§9).
- The last frontend tweak (shortened provider list) is built into your container but not re-screenshotted.

**Your running stack** (http://localhost:5173) is rebuilt with all of this. Its database still holds the audit uploads; use Demo Mode → Reset demo data for a clean slate.

---

## 8. Known limitations and risks

- **ML is advisory and noisy.** It flags benign machines (see §4.6). Do not switch to `alert` mode until retrained and re-measured.
- **"Normal" is only as good as the everyday lists** (§6 caveat). A file made only of everyday-class events reads Normal even if it is hostile in a way no rule sees; PowerShell 4103 is the most deliberate such case.
- **SMB fan-out is uncalibrated:** the benign data has no port-445 traffic; the threshold (5 hosts in 60 s, low severity) is a conservative judgement. A backup or management server may trip it.
- **Parsing is the slow part, but now bounded:** python-evtx renders about 100–235 records per second per core. Large files are read and parsed in parallel across CPU cores (up to 16 worker processes), and the upload screen shows "Reading N of M records (x%) – about Ns left", then "Analysing events". Measured inside the Docker backend container for the 56 MB / 48,125-record `sysmon_48113.evtx`: **103 s** to read and parse (133 s with 8 workers; over 6 minutes on the pre-10-October image, which read in one process). A full pipeline run in the same container (read, parse, sort, detect, store, ML; throwaway SQLite database) measured **95 s** in total: 76 s reading and 18 s for the rest, with 48,125 events and 0 rule matches. Expect roughly 1.5 to 2.5 minutes through the browser with Postgres, depending on what else the machine is doing. **After pulling new code the Docker images must be rebuilt (`docker compose up -d --build`)**, or the old reader keeps running. For a demo, a 5–10 MB capture is the practical size.
- **A Rust reader was evaluated and deliberately left off (decision, 10 October 2026).** `NIGHTOWL_EVTX_BACKEND=rust` (Linux/Docker, experimental) reads all 102 samples (348,188 records) in 16 s, but a record-by-record comparison found **0 records identical** to python-evtx: 55% of record timestamps differ by 1–2 microseconds (python-evtx's floating-point time arithmetic cannot be reproduced from the Rust output), and hex numbers, GUIDs, booleans, empty attributes, binary data and string lists are all formatted differently; 19 records are not valid XML. Event time order was unchanged in all 102 files. Because every rule, benchmark and ML feature was validated on python-evtx output, the exact reader was kept.
- **Upload jobs live in memory** (one hour, lost on restart). A lost job just means re-uploading; stored events are skipped as duplicates.
- **Unrelated sample captures from the same lab machine merge into one incident** (grouping is by host and time). This is a demo artefact, not a bug in real use.
- **The free Groq quota** runs out after roughly 45 AI calls in one sitting (benign files no longer make AI calls, which helps).
- **Hallucination:** a model can still get a detail wrong in chat; the detection time and source are now supplied to reduce it, and chat answers do not get the self-check pass explanations get.

---

## 9. What you still need to do

### 9.1 Required for "perfect" (only you can do these)

1. **Collect benign logs for the ML layer.** At least 5 more machines (a mix of laptops, desktops, servers), 3 or more normal days each, Sysmon network (event 3) logging on. Commands are in Appendix A. Then give me the folder and I will retrain, re-run the held-out check and run the upload sweep on them. Alert mode is switched on only if false windows reach about **1 per machine per day or fewer**.
2. **Look at it in your own browser** (Appendix B), especially the three unverified items in §7.
3. **Decide the push:** push `fix/production-readiness` to GitHub, and whether to open a pull request into `main` for review or merge directly. Nothing is pushed until you say so.

### 9.2 Before a real deployment

- Set `APP_ENV=production`, a 32+ character `SESSION_SECRET_KEY`, your bcrypt `ADMIN_PASSWORD_HASH` (single-quoted), `POSTGRES_PASSWORD`, `GROQ_API_KEY`, `CORS_ALLOW_ORIGINS`.
- Put a TLS-terminating reverse proxy in front and set `TRUSTED_PROXIES`.
- Keep `DEMO_MODE_ENABLED` off if the instance is public (it exposes a destructive reset).
- Review and approve the logs you collect: they contain usernames, folder names and command lines.

### 9.3 Engineering follow-ups (I can do these when you ask)

- Retrain the ML model on the new data; calibrate the SMB fan-out threshold; add any new everyday event types the new machines reveal.
- Optional faster parser on Linux only, with an output-equivalence layer.
- Persist upload jobs in the database; consider a smarter incident-grouping rule for lab samples.
- A rule or detector for the NTLM relay and a safer treatment of named-pipe discovery.
- Re-run the full browser walkthrough (with the extension, or headless) after any further change, before any push.

---

## Appendix A — Collecting benign logs (run on each machine)

Open PowerShell **as Administrator**. Copy `backend/scripts/collect_benign_logs.ps1` to the machine first.

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
New-Item -ItemType Directory C:\NightOwl -Force
# put collect_benign_logs.ps1 in C:\NightOwl\

# Sysmon from Microsoft Sysinternals
New-Item -ItemType Directory C:\Tools\Sysmon -Force
Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip -OutFile $env:TEMP\Sysmon.zip
Expand-Archive $env:TEMP\Sysmon.zip C:\Tools\Sysmon -Force

# one-time setup: Sysmon, command-line and PowerShell logging, bigger logs
cd C:\NightOwl
.\collect_benign_logs.ps1 -Setup
```

Use the machine normally for **at least 3 days**: browsing, office work, updates. Do not clear any logs and do not run hacking tools. Then, again as Administrator:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
cd C:\NightOwl
.\collect_benign_logs.ps1 -Export -OutDir C:\NightOwl\export
.\collect_benign_logs.ps1 -Revert      # optional: undo the logging changes
```

Copy each machine's `C:\NightOwl\export` folder to `backend\sample_logs\benign_collection\<PC-NAME>\`. If `-Export` warns that a log "wrapped", re-run `-Setup` with `-SysmonLogSizeMB 2048` and collect again.

## Appendix B — A visual test you can repeat

1. `docker compose up --build`, open http://localhost:5173, sign in.
2. **Settings → About:** every status dot green; the "ML model (experimental)" table lists each log family with its training windows and held-out false alarms.
3. **Demo Mode → Reset demo data**, then upload `NightOwl-Benign-Dataset/system_baseline.evtx` on the Logs page: **Normal — no threats detected**, with the everyday-event count.
4. Upload `NightOwl-Benign-Dataset/system_5000.evtx`: **Normal**, plus notes that the System, PowerShell and Sysmon logs were cleared by named accounts.
5. Upload `detected/DE_1102_security_log_cleared.evtx`: **Suspicious**; below it the "AI review of unchecked events" panel. If the free Groq quota is used up it shows a failure with a **Retry** button.
6. Upload `detected/Sysmon_UACME_32.evtx`: **Suspicious** (UAC bypass rules).
7. **Alerts → ML anomalies (experimental)** (or the "Open the ML view" link on an upload): open a record and read "What drove the score".
8. Run **Demo Mode** once end to end; open an incident, run the AI analysis, chat, change its status, check the Audit tab; sign out.

## Appendix C — Commands

```bash
cd backend
./venv/Scripts/python -m pytest                         # 778 offline tests
./venv/Scripts/python scripts/upload_sweep.py           # verdict for every sample file
./venv/Scripts/python scripts/run_detection_benchmark.py
./venv/Scripts/python scripts/build_failure_matrix.py
./venv/Scripts/python scripts/train_ml_model.py --extra-dir <folder>   # after you collect logs
./venv/Scripts/python scripts/eval_ml_model.py
cd ../frontend && npx tsc -b && npm run lint && npm run build
```

## Appendix D — Branch history (`fix/production-readiness`, newest first)

```
edfd521 shorten the provider list in the telemetry profile
53f07de demo fixtures capped at 2 MB, five detected captures moved, benchmark 57/60 and 0 FPs, docs, Postman, ML visual-check recipe
48ee98b checked/everyday/unchecked classification, log-clear notices, UserData and RPC parsing, 7 rules + SMB fan-out, AI review limits and retry, async uploads, ML model panel, upload sweep
cdd3601 keep the model's own list numbers in Markdown
7403826 regenerate the detection benchmark
849931d account/process for all Security events, audit actor, detection time in AI evidence, Markdown tables, heatmap and count fixes
92c102f CPU-only torch; single-quoted bcrypt hash for Compose
d12aff4 docs rewritten from measured results; Postman rebuilt; spot-check tool on in-memory DB
241a53d frontend: ML as experimental evidence, status badges, race/pagination/overlay fixes, honest copy
12b44f2 ML rebuilt per log family on upload-shaped windows; advisory mode; held-out evaluation
dcc2029 strict Sigma engine; 14 new rules + 5 detectors; honest benchmark
508452c AI hardening: fenced evidence, strict parsing, invented ids flagged
1273e28 backend correctness: UTC, channels, nested data, grouping, de-duplication, locks
667c8e0 security: fail-closed secret, revocable sessions, CSRF, upload guard, Docker stack
```

Restore points on GitHub: branch `backup/pre-ml` → `e6a9066`; tag `pre-latest-pull` → `b5e8d1f`.
