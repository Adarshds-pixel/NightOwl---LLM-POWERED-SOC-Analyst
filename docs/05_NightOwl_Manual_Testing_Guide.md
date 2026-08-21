# NightOwl Handbook — Volume 5: Manual Testing Guide

**Scope:** verifying everything built through **Pair 1 Day 6** (FastAPI skeleton, DB session dependency, DB models v1, Postgres/Alembic, EVTX reading + JSON conversion, normalized event schema + persistence, `POST /ingest` + robust error handling), **Pair 2 Day 6** (ChromaDB + embeddings setup, MITRE ATT&CK loader, real knowledge-base build, top-k retrieval, `GET /mitre/techniques` + rule-to-technique validator scaffold), as of **2026-08-15**; **Pair 2 Days 7–8** (explanation prompt template + Gemini LLM client wiring; explain_service's retrieve → draft → self-critique pipeline); and **Pair 1 Day 7** (detection engine v1 — Sigma rule loader + evaluator, wired into `POST /ingest`), as of **2026-08-16**. Whole suite + all live checks re-verified again on **2026-08-17** (see the "Re-verified 2026-08-17" notes throughout, and the new §14 consolidated runbook) with no regressions found; Docker Desktop was also started and Postgres brought up for the first time since 2026-08-12, fixing the `POST /ingest` HTTP 500 gap that prior days had noted as a known, environment-only limitation (not a code defect) — see §3/§9.3/§12.4's "second pass" notes. A real Gemini key was then added, which surfaced and led to fixing one genuine bug — `app/core/config.py` resolved `.env` relative to cwd instead of its own file location, so `LLM_API_KEY` was never actually read when running from `backend/` (see §10.4's "Bug found + fixed" note) — after which both live-Gemini checks (§10.4/§11.3) passed for real. Every check in this guide has now been executed for real at least once as of 2026-08-17, with no open gaps. **Pair 1 Day 8** (5 Sigma rules across process-creation/network-connection/file-creation + `alerts` table persistence, `app/services/detection_service.py`) was added and fully verified — including live persistence against real Postgres — on **2026-08-18** (§13). **Pair 1 Day 9** (5 more rules — 10 total, adding a registry category — + incident grouping, `app/services/incident_service.py`) and **Pair 1 Day 10** (severity scoring, `app/services/severity_service.py`, plus the roadmap-specified `tests/test_detection.py`) landed together and were fully verified — including live incident grouping/severity scoring against real Postgres — on **2026-08-19** (§14/§15). Pair 2's own Day 9/10 (explain endpoint, hallucination spot-check) is the teammates' responsibility and is intentionally not covered by this guide. **Pair 1 Day 11** (MITRE technique validation for every rule's tag, warn-only on unknown/deprecated/revoked ids, `app/mitre/validator.py`) and **Pair 1 Day 12** (`GET /incidents` + `GET /incidents/{id}`, 5 more rules — 15 total, covering credential access + lateral movement — consistent JSON error handling for unhandled exceptions, structured JSON logging, and an end-to-end integration test — **Milestone: Backend + Detection core complete**) were fully verified, including a Postman-based manual pass covering every endpoint, on **2026-08-19** (§18/§19/§21). **Pair 2 Day 11** (`chat_messages` service + `POST /incidents/{id}/chat` with retrieval scoped to incident context, `app/services/chat_service.py` + `app/rag/chat_service.py` + `app/api/routes_chat.py`) was added and verified via the full offline test suite (181 passed) on **2026-08-19** (§20); a live-LLM end-to-end check is still pending a Gemini free-tier quota reset (§20.3). **Pair 1 Day 13** (production hardening — `X-API-Key` header auth applied to every feature router via a new `require_api_key` dependency, `limit`/`offset` pagination on `GET /incidents` with a page-independent `total`, an in-memory token-bucket rate limiter applied to every route, and a multi-stage non-root `backend/Dockerfile` + `backend` service in `docker-compose.yml`) was added and verified via the full offline test suite (205 passed) on **2026-08-20** (§22); the Postman collection was updated the same day to cover the new auth header and pagination params (§21/§22.7). The Docker image build needed a fix for this environment's corporate-network TLS interception (see §22.6/Troubleshooting); getting a stable, working image also meant working through a stale WSL2 disk-mount lock and image layers physically corrupted by a full host disk (both diagnosed and fixed — see §22.6). **A full `docker compose up` end-to-end run is now confirmed working** — `/health` and `/mitre/techniques` (matching the non-Docker `count: 858`) both verified live from the running containers on 2026-08-20 — and the live auth (401/200) and rate-limit (429) checks in §22.4/§22.6 were re-run for real against that same live stack, not just the automated suite.

This is a hands-on runbook, not the formal Testing Report (that template lives in Volume 3 §9.5 and is for the Day 20–21 Integration & Testing phase). Every step below was executed for real against this repo on the date noted next to it — see the "Last verified" line under each step.

---

## 0. Prerequisites

- Docker Desktop installed and running (`docker info` must succeed).
- `backend/venv` already has all deps from `backend/requirements.txt` installed. If starting from a fresh clone instead:
  ```
  cd backend
  python -m venv venv
  ./venv/Scripts/pip install -r requirements.txt
  ```
- Repo root `.env` must exist (copy from the template if missing):
  ```
  cp .env.example .env
  ```
- **Windows + corporate/AV network only:** if you hit `SSLError: CERTIFICATE_VERIFY_FAILED` when anything tries to reach GitHub/HuggingFace (this environment's default network intercepts TLS via a root CA that's trusted by Windows but not by Python's bundled `certifi`), install once per venv:
  ```
  ./venv/Scripts/python.exe -m pip install pip-system-certs
  ```
  This makes Python trust the same certificate store Windows/curl already trust. No app code changes needed — confirmed as the fix here.
- **If `pip install -r requirements.txt` fails on `Failed to build 'hexdump'` / `AssertionError` in `_distutils_hack`** (a `python-evtx` sub-dependency hitting a setuptools/distutils conflict on Python 3.10 — seen on this machine): set `SETUPTOOLS_USE_DISTUTILS=stdlib` for the install, which disables setuptools' local-distutils override hack instead of asserting on it:
  ```
  SETUPTOOLS_USE_DISTUTILS=stdlib ./venv/Scripts/python.exe -m pip install -r requirements.txt
  ```
  Confirmed as the fix here — no app code changes needed, only needed once per venv (already-installed packages are skipped on repeat runs without the env var).
- Only the Postgres/Alembic (§3) and DB-touching parts of the live-server check (§4) need Docker; everything else in this guide works without it. If Docker Desktop isn't installed at all (not just stopped) `docker info`/`docker --version` fail with "command not found" rather than a connection error — install it from docker.com before attempting §3.

---

## 1. Offline unit tests (no network, no DB)

```
cd backend
./venv/Scripts/python.exe -m pytest tests/test_health_and_models.py -v
```

Covers:
- `test_health_check` — FastAPI `/health` via `TestClient`.
- `test_models_register_expected_tables`, `test_models_create_all_against_sqlite` — all 5 SQLAlchemy models register and `create_all()` cleanly against in-memory SQLite.

**Expected:** `3 passed`.
**Last verified:** 2026-08-12 — 3 passed in 1.16s.
**Re-verified 2026-08-15:** `3 passed in 1.41s`.
**Re-verified 2026-08-17:** covered as part of the full 90-test regression run (§6) — passed.

---

## 2. Network-dependent RAG/MITRE tests

```
cd backend
./venv/Scripts/python.exe -m pytest tests/test_setup_integrations.py -v
```

Covers:
- `test_chroma_add_and_query` — ChromaDB `PersistentClient`, upsert + query round-trip.
- `test_embedding_shape` — `sentence-transformers` (`all-MiniLM-L6-v2`) produces a 384-dim vector.
- `test_mitre_loader_has_known_technique` — downloads/parses the official MITRE ATT&CK Enterprise STIX bundle (pinned to `ATT&CK-v19.2`), asserts 500+ techniques and that `T1059.001` ("PowerShell") is present.

Needs outbound internet (GitHub raw + HuggingFace Hub for model weights on first run — subsequent runs use local caches and are much faster).

**Expected:** `3 passed` (first run ~80–90s while the embedding model downloads; cached runs are seconds).
**Last verified:** 2026-08-12 — 3 passed in 84.61s.
**Re-verified 2026-08-15:** `3 passed` (cached run, combined with §7's Day 4 EVTX tests: `7 passed in 25.71s`).
**Re-verified 2026-08-17:** covered as part of the full 90-test regression run (§6) — passed.

---

## 3. Live Postgres + Alembic migration

```
cd <repo root>
docker compose up -d db
```

Wait for it to be healthy:
```
docker compose exec db pg_isready -U nightowl
```

Apply the migration:
```
cd backend
./venv/Scripts/python.exe -m alembic upgrade head
./venv/Scripts/python.exe -m alembic current   # should print: fa0ac08ab62f (head)
```

Verify the 5 core tables exist:
```
docker compose exec db psql -U nightowl -d nightowl -c "\dt"
```

**Expected:** `alembic_version`, `alerts`, `chat_messages`, `events`, `incidents`, `rules` — 6 tables.
**Last verified:** 2026-08-12 — all 6 tables present, `alembic current` = `fa0ac08ab62f (head)`. This was the first time the migration had been run against a live Postgres instance rather than only the in-memory SQLite used by tests.

> **Not re-verified 2026-08-15:** Docker itself isn't installed on this machine (`docker`/`docker info` both fail with "command not found", not just "daemon not running"). §1/§2/§6 (all SQLite/Chroma-backed) and §4's `/health` route don't need it and were re-confirmed working standalone. Install Docker Desktop to re-run this section here.

> **Resolved 2026-08-17:** Docker Desktop is now installed on this machine (`docker --version` → `29.4.1`) but its daemon wasn't running by default — started via `Docker Desktop.exe`, daemon ready within seconds. Re-ran this section for real: `docker compose up -d db` → container created and started cleanly, `pg_isready` succeeded, `alembic upgrade head` applied with no errors, `alembic current` → `fa0ac08ab62f (head)`, and `\dt` confirmed all 6 tables (`alembic_version`, `alerts`, `chat_messages`, `events`, `incidents`, `rules`). Postgres data persists in a named Docker volume across `down`/`up` cycles — the `events` table already had 8 rows from earlier (2026-08-12-era) verification sessions before this run added 4 more via §9.3's re-verified happy path. Docker Desktop does not auto-start with Windows on this machine, so it needs to be launched manually each session before this section will work.

---

## 4. Live FastAPI server smoke test

```
cd backend
./venv/Scripts/python.exe -m uvicorn app.main:app --port 8000
```
In another shell:
```
curl http://127.0.0.1:8000/health
```

**Expected:** `{"status":"ok"}`, HTTP 200.
**Last verified:** 2026-08-12 — confirmed `{"status":"ok"}` / HTTP 200 outside of the `TestClient` harness. Stop the server afterward (Ctrl+C, or on Windows find the PID with `netstat -ano | findstr :8000` and `taskkill /F /PID <pid>`).
**Re-verified 2026-08-15 (Docker not installed on this machine):** `/health` doesn't touch the DB (`app/main.py` builds no engine/session at import time), so the server starts and responds `{"status":"ok"}` / HTTP 200 even with no Postgres available at all — confirming this route has no hidden DB dependency.

---

## 5. Real knowledge-base build (Pair 2 Day 4 deliverable)

```
cd backend
./venv/Scripts/python.exe scripts/build_kb.py
```

Downloads/parses the MITRE dataset, chunks all non-deprecated/non-revoked techniques plus the 5 playbooks under `data/knowledge_base/playbooks/`, embeds them with the project's own `sentence-transformers` wrapper (not Chroma's default embedding function), and upserts into the `knowledge_base` Chroma collection.

**Expected:** a summary line like `MITRE techniques: N processed, M skipped (deprecated/revoked)`, `Playbooks: 5 processed`, and a final `Upserted <count> chunks into Chroma collection 'knowledge_base' (<count> total in collection)`.
**Last verified:** 2026-08-12 — 697 techniques processed, 161 skipped (deprecated/revoked), 5 playbooks processed, 1888 total chunks upserted.
**Re-verified 2026-08-15:** identical counts (697/161/5/1888) — confirms the build is stable/idempotent (Chroma `upsert` on unchanged source data doesn't change the collection).

---

## 6. Full regression pass

All 34 tests are pure-Python/in-memory-SQLite/local-Chroma — none need live Postgres, so this runs standalone (Docker not required):
```
cd backend
./venv/Scripts/python.exe -m pytest -v
```

**Expected:** all tests pass together (34 as of Day 5 — 6 from Day 3, 4 from Day 4, 24 from Day 5: 21 normalization/persistence + 3 retrieval).
**Last verified:** 2026-08-15 — `34 passed in 31.61s`.
**Re-verified 2026-08-17:** superseded by the larger §12.2 full-suite run (90 tests as of Day 7/8) — `90 passed in 39.85s`, no failures, no regressions.

> **Resolved (2026-08-15):** this venv was previously missing `fastapi`/`sqlalchemy`/`python-evtx` (Pair 1's Day 3+ deps) because `pip install -r requirements.txt` failed on `python-evtx`'s `hexdump` sub-dependency (`AssertionError` in `_distutils_hack`). Fixed with the `SETUPTOOLS_USE_DISTUTILS=stdlib` workaround now documented in Prerequisites (§0) — all 34 tests collect and pass together as of this run.

---

## 7. Day 5 — Event normalization + persistence (Pair 1 Day 5 deliverable, offline)

```
cd backend
./venv/Scripts/python.exe -m pytest tests/ingestion/test_normalizer.py tests/services/test_event_service.py -v
```

Covers:
- `ingestion/test_normalizer.py` — maps hand-crafted Sysmon-shaped records (the repo's only `sample.evtx` is Windows System-log data, not Sysmon, so real event ID 1/3/11 fixtures aren't available in the file itself) to `NormalizedEvent` for event IDs 1 (process creation → `process`/`command_line`/`user`), 3 (network connection → `protocol`/`source_ip`/`source_port`/`destination_ip`/`destination_port`), and 11 (file create → `target_filename`); handles `EventID` as a plain string vs. a qualifier dict, `EventData.Data` as a single dict vs. a list, and empty `<Data>` elements; confirms unrecognized event IDs still normalize (common fields only, no exception) and that genuinely malformed records (`Event`/`System` missing, `EventID`/`TimeCreated` unparseable) raise `EventNormalizationError`.
- `services/test_event_service.py` — in-memory SQLite (same pattern as `test_health_and_models.py`), confirms `create_event`/`save_events` persist the `Event` row's flat columns from a `NormalizedEvent`, that `raw_json` holds both the original raw record and the normalized view (`{"raw": ..., "normalized": ...}`) so fields not yet promoted to flat columns aren't lost, that a batch commits and logs `"ingested N events"`, and that a persisted row round-trips correctly when queried back.

**Expected:** `21 passed`.
**Last verified:** 2026-08-14 — 21 passed in 0.97s.
**Re-verified 2026-08-15:** `21 passed in 0.98s`.

### 7.1. Real Sysmon sample (superseded — kept for process history only)

> **Superseded by §7.2's `sysmon_demo.evtx`.** `sysmon_sample.evtx` (this section) was never committed — it's a strict subset of `sysmon_demo.evtx` (same 3 ID 1 records, minus the ID 11 record §7.2 added), so it was left out of the repo as redundant rather than checked in alongside its superset. The steps below are kept so the capture process/reasoning stays documented, but the file itself is not present in `data/sample_logs/`.

The Day 5 unit tests above use hand-crafted fixture dicts because the repo's only `sample.evtx` is Windows System-log data, not Sysmon. To get a genuine end-to-end fixture for Day 6's ingest endpoint, a real (but minimal, deliberately-triggered) Sysmon sample was captured from a dev laptop with Sysmon already installed and running.

**How it was generated** (requires an elevated PowerShell window — reading `Microsoft-Windows-Sysmon/Operational` needs admin rights):
```powershell
cmd.exe /c whoami | Out-Null
curl.exe -s -o NUL https://example.com
$testFile = "$env:TEMP\nightowl_test_file.txt"
"nightowl sysmon sample test" | Out-File $testFile
Remove-Item $testFile
Start-Sleep -Seconds 3

$xpath = "*[System[(EventID=1 or EventID=3 or EventID=11) and TimeCreated[timediff(@SystemTime) <= 300000]]]"
wevtutil epl Microsoft-Windows-Sysmon/Operational "$env:TEMP\sysmon_sample.evtx" /q:$xpath
```

A first pass with this time-window filter captured 356 records — all Event ID 1, and it swept in 353 unrelated ambient process launches from other running apps, not just the 3 deliberate actions. It was then trimmed to only the 3 target records by re-exporting with an `EventRecordID`-based XPath filter instead of a time window:
```powershell
$xpath = "*[System[(EventRecordID=932193 or EventRecordID=932194 or EventRecordID=932197)]]"
wevtutil epl Microsoft-Windows-Sysmon/Operational "$env:TEMP\sysmon_sample_trimmed.evtx" /q:$xpath
```

**Known gap — Event ID 3 and 11 are not present in this sample.** `sysmon.exe -c` on this machine showed `No rules installed` and `Network connection: disabled` — this Sysmon deployment only logs ProcessCreate (ID 1); NetworkConnect and FileCreate aren't enabled at all, regardless of what real activity happens. Enabling them would mean deploying a new Sysmon config XML on the live machine, which is a change to real endpoint monitoring, not just this repo — out of scope here. ID 3/11 mapping stays covered by the hand-crafted fixtures in `ingestion/test_normalizer.py`; `sysmon_sample.evtx` is real-world ID 1 data only.

**Verification pass** (read + normalize, manual — not wired into pytest, since a machine-specific real file shouldn't be a hard dependency of the automated suite):
```
cd backend
./venv/Scripts/python.exe -c "
from app.ingestion.evtx_reader import read_records_as_dicts
from app.ingestion.normalizer import normalize_event

records = list(read_records_as_dicts('../data/sample_logs/sysmon_sample.evtx'))
for r in records:
    n = normalize_event(r)
    print(n.event_id, n.host, n.process, n.command_line)
"
```

**Expected:** 3 records, all `event_id=1`, none raise `EventNormalizationError`.
**Last verified:** 2026-08-14 —
```
event_id=1 host=LAPTOP-5GVGMJ14 process=C:\Windows\System32\cmd.exe      command_line='"C:\Windows\system32\cmd.exe" /c whoami'
event_id=1 host=LAPTOP-5GVGMJ14 process=C:\Windows\System32\whoami.exe   command_line='whoami'
event_id=1 host=LAPTOP-5GVGMJ14 process=C:\Windows\System32\curl.exe    command_line='"C:\Windows\system32\curl.exe" -s -o NUL https://example.com'
```
`ingestion/test_evtx_reader.py` and `ingestion/test_normalizer.py`/`services/test_event_service.py` re-run afterward, unaffected: `25 passed in 1.77s`.

### 7.2. Second real capture (`data/sample_logs/sysmon_demo.evtx`) — adds ID 11, investigates ID 3

A second real capture was made to try to get closer to full ID 1/3/11 coverage, using a **scoped** Sysmon config change instead of the broad default rule set, to keep the blast radius minimal:
```xml
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <NetworkConnect onmatch="include">
      <Image condition="is">C:\Windows\System32\curl.exe</Image>
    </NetworkConnect>
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">nightowl_test_file</TargetFilename>
    </FileCreate>
  </EventFiltering>
</Sysmon>
```
Applied via `sysmon.exe -c <config>` (elevated), immediately followed by the same 3 harmless actions (`whoami`, `curl.exe https://example.com`, a named temp-file write+delete), then reverted via an empty-`EventFiltering` config right after export. This only logs network connections *from curl.exe* and file creates matching our unique test filename — nothing else on the machine — and was tried twice (once with an added 8-second arm delay) to rule out a driver-startup timing issue.

**Result: FileCreate (ID 11) worked both times. NetworkConnect (ID 3) never fired, in either attempt.**

**Root cause (confirmed via read-only diagnostics, no security product touched):**
- `curl.exe` genuinely completed a real TLS connection to example.com (`curl -v` showed a full handshake + `HTTP/1.1 200 OK`) — the network activity we needed did happen.
- Sysmon's config change *was* accepted both times (`Get-WinEvent` against the Operational log shows 4 real `Event ID 16` "config state changed" entries with matching file hashes for our exact config/revert files).
- `SysmonDrv` (the kernel driver) is running.
- But a full WFP (Windows Filtering Platform) state dump (`netsh wfp show state`, 5.3MB) has **zero** entries for Sysmon — its network-monitoring callout never actually registered with the OS network stack, regardless of what the config said.
- This machine runs **McAfee** as the active AV/firewall (`mc-fw-host` = McAfee Framework Host, a WFP-based component), while Windows Defender's own real-time protection and network inspection service are stopped (standard single-active-AV arbitration). One security vendor's network-filter driver claiming priority over the WFP layers another needs is a known conflict pattern, and matches what's observed here: accepted config, running driver, zero actual filtering, no visible error.
- Contributing factor: this machine's `sysmon.exe` reports version `10.0.26100.8521` (matching the Windows 11 24H2 build number), i.e. this is the **Windows-inbox/integrated Sysmon**, not the standalone Sysinternals `Sysmon64.exe` most public detection guidance assumes — its network-monitoring behavior under a conflicting AV stack may differ from the classic tool.

Per explicit decision, this was **not** worked around by touching McAfee, Defender, firewall, or any other security product config — real ID 3 stays unobtained on this specific machine.

**Verification** (same read + normalize pattern as §7.1):
```
cd backend
./venv/Scripts/python.exe -c "
from app.ingestion.evtx_reader import read_records_as_dicts
from app.ingestion.normalizer import normalize_event

records = list(read_records_as_dicts('../data/sample_logs/sysmon_demo.evtx'))
for r in records:
    n = normalize_event(r)
    print(n.event_id, n.host, n.process, n.command_line, n.target_filename)
"
```
**Expected:** 4 records — 3× `event_id=1` (cmd.exe, whoami.exe, curl.exe process creations), 1× `event_id=11` (the named temp file), none raise `EventNormalizationError`.
**Last verified:** 2026-08-14 — all 4 normalized cleanly as expected; full suite re-run afterward: `31 passed in 40.24s`.
**Re-verified 2026-08-15:** identical output (3× `event_id=1`, 1× `event_id=11`, none raised); full suite re-run afterward: `34 passed in 31.61s`.

**Planned future method for real ID 3 (not built yet — Path A, deferred):**
1. Clean Windows VM/sandbox with no conflicting AV.
2. Install standalone Sysinternals `Sysmon64.exe`.
3. Minimal config enabling only `ProcessCreate` + `NetworkConnect` + `FileCreate`.
4. Generate the same kind of controlled/harmless test activity used here.
5. Capture, then validate through NightOwl's existing `evtx_reader.py` + `normalizer.py` (no code changes expected).
6. Host machine (this laptop) stays untouched throughout — the VM is fully separate.

This is scoped as a standalone future task, not attempted as part of Day 5.

---

## 8. Day 5 — Retrieval (Pair 2 Day 5 deliverable)

### 8.1. Automated tests

```
cd backend
./venv/Scripts/python.exe -m pytest tests/rag/test_retriever.py -v
```

Covers `backend/app/rag/retriever.py`'s `retrieve(query, k, source_type, technique_id)`:
- `test_retrieve_returns_k_results_ranked_by_score` — returns exactly `k` hits, scores strictly descending, at least one `source_type` in `{mitre_technique, playbook}`.
- `test_retrieve_technique_id_filter_restricts_results` — the `technique_id` metadata filter actually restricts Chroma's `where` clause (all returned hits match `T1059.001`).
- `test_retrieve_source_type_filter_restricts_results` — same for the `source_type` filter (`playbook`).

**Expected:** `3 passed`.
**Last verified:** 2026-08-15 — `3 passed` (in ~28-34s combined with the Day 3 RAG tests, embedding model load dominates).

### 8.2. Manual smoke test

```
cd backend
./venv/Scripts/python.exe -m app.rag.retriever
```

Runs `retrieve("obfuscated powershell command line", k=3)` against the real `knowledge_base` collection populated in Day 4.

**Expected:** 3 lines of `<score>  <chunk_id>  <document snippet>`, all PowerShell/command-obfuscation related, highest score first.
**Last verified:** 2026-08-15 —
```
0.6179  mitre:T1027.010:1  'eter](https://attack.mitre.org/techniques/T1059).(Citation: Akamai JS)(Citation:'
0.5403  mitre:T1027.010:0  'Command Obfuscation Adversaries may obfuscate content during command execution t'
0.5376  mitre:T1059.001:0  'PowerShell Adversaries may abuse PowerShell commands and scripts for execution. '
```

### 8.3. Manual retrieval-quality check (roadmap-required deliverable)

The roadmap requires manually testing 10 queries and verifying retrieved chunks make sense — done and written up in full in [`docs/research/retrieval-eval.md`](research/retrieval-eval.md) (not duplicated here). Spot-check reproduction:

```
cd backend
./venv/Scripts/python.exe -c "
from app.rag.retriever import retrieve
for h in retrieve('scheduled task created for persistence', k=4):
    print(h['score'], h['chunk_id'], h['metadata'].get('technique_name') or h['metadata'].get('title'))
"
```

**Expected:** top hits are `T1053.005`/`playbook:T1053_005_scheduled_task_persistence` chunks.
**Last verified:** 2026-08-15 —
```
0.6247727607796864 playbook:T1053_005_scheduled_task_persistence:1 Scheduled Task Persistence Response Playbook
0.6228405693455012 mitre:T1053.005:0 Scheduled Task
0.5716664856770546 playbook:T1053_005_scheduled_task_persistence:2 Scheduled Task Persistence Response Playbook
0.5233292607942249 playbook:T1053_005_scheduled_task_persistence:0 Scheduled Task Persistence Response Playbook
```
Matches `docs/research/retrieval-eval.md` exactly (§2 there). **Known finding, not a bug:** C2/"beaconing"-phrased queries don't surface the `T1071.001` web-protocol-C2 playbook in a practical top-k, even though it's correctly ingested — see that doc's "Issue found" section for the full writeup and the Day 7+ mitigation recommended (retrieve with the Sigma-matched `technique_id` filter when it's already known, rather than free-text alone).

---

## 9. Day 6 — Ingest API (Pair 1 deliverable) + MITRE endpoint & validator scaffold (Pair 2 deliverable)

### 9.1. Automated tests

```
cd backend
./venv/Scripts/python.exe -m pytest tests/api/test_ingest_route.py tests/api/test_mitre_route.py tests/mitre/test_validator.py -v
```

Covers:
- `api/test_ingest_route.py` (Pair 1) — `POST /ingest` end-to-end against the real `sysmon_demo.evtx` fixture (via `TestClient` + an in-memory SQLite override of `get_db`), plus the three named failure modes: wrong extension, empty file, malformed/corrupted EVTX bytes (`test_ingest_rejects_corrupted_evtx_bytes` covers both a too-short garbage payload and a realistic-size one, see the bug note below); and that a malformed *record* inside an otherwise-good file is skipped and counted, not treated as a whole-upload failure.

> **Bug found and fixed (2026-08-19):** the Postman collection's "Ingest - Malformed EVTX (expect 400)" request, run live against a `.evtx`-renamed 50-byte garbage file (`fake.evtx`), returned `200` with an all-zero success body instead of `400`. Root cause: `python-evtx` doesn't validate the EVTX magic bytes on its own — for garbage content ≥ ~44 bytes it silently reports zero chunks/records instead of raising, so `evtx_reader.py` had nothing to catch and convert into a 400. (Content < ~44 bytes fails an internal struct unpack and *did* already raise correctly, which is why the original `test_ingest_rejects_corrupted_evtx_bytes` — using a 32-byte payload — never caught this.) **Fix:** `read_raw_records()` in `app/ingestion/evtx_reader.py` now explicitly checks `log.get_file_header().check_magic()` right after opening the file and raises `EvtxReadError` if it fails, before iterating records — this catches bad EVTX content regardless of size. `test_ingest_rejects_corrupted_evtx_bytes` was extended (not duplicated, so the suite's total count is unaffected) to also assert 400 for a realistic-size garbage payload. No live-server/Postgres re-verification needed — this rejection happens before any DB call, same as the other two error cases.
- `api/test_mitre_route.py` (Pair 2) — `GET /mitre/techniques` returns the full catalog sorted by ID, includes `is_deprecated`/`is_revoked` flags per entry, and handles an empty lookup cleanly. `load_mitre_techniques` is monkeypatched to a small fixed lookup so this test doesn't depend on the full downloaded MITRE dataset.
- `mitre/test_validator.py` (Pair 2) — `mitre/validator.py`'s `validate_technique_id`/`validate_technique_ids` scaffold: valid ID, unknown ID, deprecated-flagged ID, revoked-flagged ID, and the batch form. Also monkeypatched against a fixed lookup.

**Expected:** `13 passed`.
**Last verified:** 2026-08-15 — `13 passed in 2.24s`.
**Re-verified 2026-08-17:** covered as part of the full 90-test regression run (§12.2) — passed.

### 9.2. Full regression pass

```
cd backend
./venv/Scripts/python.exe -m pytest -v
```

**Expected:** `47 passed` (34 from Day 3–5 + 13 from Day 6).
**Last verified:** 2026-08-15 — `44 passed, 3 failed in 90.64s`. The 3 failures are all in `tests/rag/test_retriever.py` (`retrieve()` returning 0 hits against the real `knowledge_base` Chroma collection in this environment) — pre-existing as of this run, unrelated to any Day 6 code (neither `routes_ingest.py`, `routes_mitre.py`, nor `validator.py` touch `rag/retriever.py` or the Chroma collection), and not fixed as part of Day 6. Flagged here for Kiran/the team to look into before Day 7 builds the LLM/prompt layer on top of retrieval — see §8.1 for the isolated repro.

> **Resolved (2026-08-16):** re-ran `pytest -v` before starting Day 7 — `47 passed in 29.03s`, all 3 `rag/test_retriever.py` cases now green. On-disk inspection (sqlite embedding row count, HNSW segment file size, a live `retrieve()` call) showed a complete, consistent index; the most likely explanation is a transient stale on-disk index state on 2026-08-15 that resynced on a later write/read cycle. No change was needed in `retriever.py`/`chroma_client.py`.

### 9.3. Live server smoke test — `POST /ingest` (Pair 1)

```
cd backend
./venv/Scripts/python.exe -m uvicorn app.main:app --port 8000
```
In another shell (from `backend/`, so the relative sample-log path resolves):
```
curl -F "file=@../data/sample_logs/sysmon_demo.evtx;type=application/octet-stream" http://127.0.0.1:8000/ingest
```

**Expected without a live Postgres instance (this machine — Docker not installed, see §3):** HTTP 500 — the route's own logic runs fine (file validated, EVTX parsed, events normalized), but `save_events`'s DB commit fails with `psycopg2.OperationalError: connection to server ... port 5433 failed: Connection refused`. This is the same Docker-not-installed gap noted in §3/§4, not a Day 6 defect — confirmed by the traceback pointing at the DB flush step, after parsing already succeeded.
**With Postgres running** (`docker compose up -d db` + `alembic upgrade head`, per §3): expect HTTP 200 and
```json
{"filename":"sysmon_demo.evtx","records_read":4,"events_ingested":4,"events_skipped":0}
```
**Last verified:** 2026-08-15 — HTTP 500 as above (no Postgres on this machine); the identical request path is covered end-to-end against SQLite by the automated test in §9.1, so the DB-write logic itself is confirmed working — only this specific live/Postgres combination is unverified on this machine.
**Re-verified 2026-08-17 (first pass, before Docker was started):** same HTTP 500, same `psycopg2.OperationalError ... port 5433 ... Connection refused` traceback confirmed in the server log — no change from prior days.
**Re-verified 2026-08-17 (second pass, after starting Docker Desktop + `docker compose up -d db` + `alembic upgrade head`, per §3's resolution note):** HTTP 200 —
```json
{"filename":"sysmon_demo.evtx","records_read":4,"events_ingested":4,"events_skipped":0,"rule_matches":0,"matched_rule_titles":[]}
```
(the two extra fields are Day 7's detection-engine additions, see §12.4 — not present in the original Day 6 example above). Confirmed the 4 new rows actually landed in Postgres (`SELECT COUNT(*) FROM events` went from 8 → 12). The previously-documented HTTP 500 was never a code defect — it was purely this machine not having Postgres up; with Postgres available the same route returns 200 as designed.

The three error-handling cases (all pure validation/parsing, no DB touched, so they work with or without Postgres):
```
curl -F "file=@<path-to-a-non-evtx-file>;type=text/plain" http://127.0.0.1:8000/ingest
curl -F "file=@<path-to-a-0-byte-file>;type=application/octet-stream" http://127.0.0.1:8000/ingest
curl -F "file=@<path-to-a-file-with-a-few-garbage-bytes>;type=application/octet-stream" http://127.0.0.1:8000/ingest
```
**Expected:** all three HTTP 400, with `detail` messages `"unsupported file type: expected '.evtx', got '<name>'"`, `"uploaded file is empty"`, and `"failed to parse EVTX file: ..."` respectively.
**Last verified:** 2026-08-15 — all three reproduced exactly as expected.
**Re-verified 2026-08-17:** all three reproduced again, byte-for-byte identical `detail` messages.

> **Windows/git-bash `curl` gotcha:** if your fixture file path starts with `/` (e.g. `/tmp/foo.txt`), `curl -F "file=@/tmp/foo.txt"` fails with `curl: (26) Failed to open/read local data from file/application` — this environment's `curl.exe` is a native mingw64 binary that only path-translates a POSIX path when it *leads* the argument; embedded after `-F file=@`, it's passed through literally and Windows can't resolve it. Fix: use a path relative to your shell's cwd (as above), or convert to a Windows path first with `cygpath -w /tmp/foo.txt`.

### 9.4. Live server smoke test — `GET /mitre/techniques` (Pair 2)

With the same server running (no DB needed — this route only reads the cached `data/mitre/enterprise-attack.json` via `mitre/loader.py`):
```
curl http://127.0.0.1:8000/mitre/techniques
```

**Expected:** HTTP 200, a JSON object `{"techniques": [...], "count": N}`, techniques sorted by ID, each with `id`/`name`/`description`/`tactics`/`is_deprecated`/`is_revoked`.
**Last verified:** 2026-08-15 — HTTP 200, `count: 858`, first entry `T1001` ("Data Obfuscation"), last entry `T1690` ("Prevent Command History Logging"), `T1059.001` present with `tactics: ["execution"]`, `is_deprecated: False`, `is_revoked: False`. Confirms this route has no hidden DB dependency, same as `/health` in §4.
**Re-verified 2026-08-17:** identical response — `count: 858`, same first/last entries, same `T1059.001` flags.

### 9.5. Manual smoke test — `mitre/validator.py` scaffold (Pair 2)

```
cd backend
./venv/Scripts/python.exe -c "
from app.mitre.validator import validate_technique_id, validate_technique_ids

print(validate_technique_id('T1059.001'))
print(validate_technique_id('T9999.999'))
print(validate_technique_ids(['T1059.001', 'T1003', 'T9999.999']))
"
```

**Expected:** a valid, non-deprecated/non-revoked result for `T1059.001`; `is_valid=False` for the made-up `T9999.999`; and a dict keyed by all three IDs for the batch call.
**Last verified:** 2026-08-15 —
```
TechniqueValidationResult(technique_id='T1059.001', is_valid=True, is_deprecated=False, is_revoked=False)
TechniqueValidationResult(technique_id='T9999.999', is_valid=False, is_deprecated=False, is_revoked=False)
{'T1059.001': TechniqueValidationResult(technique_id='T1059.001', is_valid=True, is_deprecated=False, is_revoked=False), 'T1003': TechniqueValidationResult(technique_id='T1003', is_valid=True, is_deprecated=False, is_revoked=False), 'T9999.999': TechniqueValidationResult(technique_id='T9999.999', is_valid=False, is_deprecated=False, is_revoked=False)}
```
This is a scaffold only — real per-rule-file validation logic (reading `detection/rules/*.yml`, deciding the deprecated/revoked acceptance policy) is Pair 1's Day 11 task; this confirms the interface they'll call is present and correct.

---

## 10. Day 7 — Prompt + LLM wiring (Pair 2 deliverable)

### 10.1. Automated tests

```
cd backend
./venv/Scripts/python.exe -m pytest tests/rag/test_prompts.py tests/rag/test_llm_client.py -v
```

Covers:
- `rag/test_prompts.py` — `rag/prompts.py`'s `format_incident_context`/`format_chunks`/`build_explanation_prompt`: renders incident fields, drops empty ones, formats retrieved chunks (score + metadata + document text) in `retriever.retrieve()`'s exact shape, and confirms the rendered prompt is exactly a `[SystemMessage, HumanMessage]` pair with the grounding rules and technique ID embedded correctly. Handles empty incident/chunks input.
- `rag/test_llm_client.py` — `rag/llm_client.py`'s `get_llm_client`/`generate`: raises `LLMProviderError` when `LLM_API_KEY` is unset (no key needed to run this — that's the point); constructs `ChatGoogleGenerativeAI` with the configured model/key; caches the client instance; returns the mocked response content on success; retries once then raises after repeated failure; recovers if the retry succeeds; raises on an empty response. `ChatGoogleGenerativeAI` is fully mocked (`monkeypatch`, same pattern as `mitre/test_validator.py`'s `load_mitre_techniques` mocking) — fully offline, no network call, no real API key used.

**Expected:** `16 passed`.
**Last verified:** 2026-08-16 — `16 passed in 12.59s`.
**Re-verified 2026-08-17:** covered as part of the full 90-test regression run (§12.2) — passed.

### 10.2. Full regression pass

```
cd backend
./venv/Scripts/python.exe -m pytest -v
```

**Expected:** `63 passed` (47 from Day 3–6 + 16 from Day 7).
**Last verified:** 2026-08-16 — `63 passed in 27.77s`.
**Re-verified 2026-08-17:** superseded by the larger §12.2 full-suite run (90 tests as of Day 7/8) — `90 passed in 39.85s`.

### 10.3. Manual prompt-rendering smoke test (no API key needed)

```
cd backend
./venv/Scripts/python.exe -m app.rag.prompts
```

**Expected:** prints the rendered system message (grounding rules) followed by the rendered human message (sample incident context + one retrieved chunk).
**Last verified:** 2026-08-16 — rendered exactly as expected; system message carries the "What happened"/"Why it matters"/"Recommended next steps" structure, human message embeds `WIN10-ANALYST` and `T1059.001`.
**Re-verified 2026-08-17:** identical output, byte-for-byte.

### 10.4. Manual end-to-end LLM smoke test

```
cd backend
./venv/Scripts/python.exe -m app.rag.llm_client
```

Chains `prompts.build_explanation_prompt()` into `llm_client.generate()` for a real call to Gemini. Requires a real `LLM_API_KEY` in `.env` (free key at https://aistudio.google.com/apikey).

**Expected:** a ~150–300 word explanation of the sample PowerShell incident, structured into the three headed sections defined in `SYSTEM_PROMPT`.
**Last verified:** 2026-08-16 — real call against `gemini-flash-latest` succeeded, returned a correctly-structured "What happened" / "Why it matters" / "Recommended next steps" explanation referencing `T1059.001`.
**Not re-verified 2026-08-17 (first pass):** `LLM_API_KEY` is empty in this machine's `.env` today, so this live-Gemini check was skipped rather than faked. `rag/test_llm_client.py`'s fully-mocked automated tests (§10.1) still cover the request/response logic offline.

> **Bug found + fixed 2026-08-17:** after a real key was added to `.env`, this step still raised `LLMProviderError: LLM_API_KEY is not set` even though the key was present. Root cause: `Settings.model_config` in `app/core/config.py` used `env_file=".env"`, a path pydantic-settings resolves **relative to the process's current working directory** — but every command in this guide runs from `backend/`, while the real `.env` lives at the repo root. Since Postgres's `DATABASE_URL` default happens to match `.env.example`'s value, this silently never surfaced there, but `LLM_API_KEY`'s empty-string default made it fail loudly. Fixed by resolving the `.env` path from `config.py`'s own file location instead of cwd: `_ENV_FILE = Path(__file__).resolve().parents[3] / ".env"`. Full 90-test suite re-run after the fix: `90 passed in 31.98s`, no regressions.

**Re-verified 2026-08-17 (second pass, after the config.py fix):** real call against `gemini-flash-latest` succeeded — a correctly-structured "What happened" / "Why it matters" / "Recommended next steps" explanation referencing `T1059.001`, `WIN10-ANALYST`, and `jdoe`. Matches the 2026-08-16 baseline in structure and content.

> **Bug found + fixed during this verification:** the current `langchain-google-genai` (4.3.4) returns `AIMessage.content` as a list of content blocks (`[{"type": "text", "text": ..., "extras": {"signature": ...}}]`), not a plain string as `generate()` originally assumed. This silently passed the raw list through instead of raising or returning text. Fixed in `llm_client.py` with a `_extract_text()` helper that concatenates `type: "text"` blocks (and passes plain strings through unchanged, so older/other providers still work); covered by a new regression test, `test_generate_extracts_text_from_content_block_list`, in `rag/test_llm_client.py`.

---

## 11. Day 8 — Explanation generation with self-critique (Pair 2 deliverable)

### 11.1. Automated tests

```
cd backend
./venv/Scripts/python.exe -m pytest tests/rag/test_explain_service.py -v
```

Covers `rag/explain_service.py`'s `generate_explanation()`: builds a retrieval query from whatever incident fields are present (falls back to `"security incident"` if the incident dict is empty); passes `k` and `technique_id` through to `retriever.retrieve()`; when the self-critique pass responds `"No issues found."`, the returned `explanation` equals the draft unchanged; when the critique flags an unsupported claim, the returned `explanation` is the draft plus an appended `**Confidence check:**` section containing the critique text; an `LLMProviderError` from either the draft or critique call propagates to the caller rather than being swallowed. `retriever.retrieve` and `llm_client.generate` are both mocked — fully offline, no network call, no real API key used.

**Expected:** `6 passed`.
**Last verified:** 2026-08-16 — `6 passed in 13.47s`.
**Re-verified 2026-08-17:** covered as part of the full 90-test regression run (§12.2) — passed.

### 11.2. Full regression pass

```
cd backend
./venv/Scripts/python.exe -m pytest -v
```

**Expected:** `70 passed` (47 from Day 3–6 + 17 from Day 7 + 6 from Day 8 — Day 7 count includes the content-block regression test added during Day 8's verification).
**Last verified:** 2026-08-16 — `70 passed in 47.19s`.
**Re-verified 2026-08-17:** superseded by the larger §12.2 full-suite run (90 tests as of Day 7's detection engine) — `90 passed in 39.85s`.

### 11.3. Manual end-to-end smoke test — real retrieval + real Gemini calls

```
cd backend
./venv/Scripts/python.exe -m app.rag.explain_service
```

Runs the full pipeline against the real `knowledge_base` Chroma collection and a real Gemini call for both the draft and the self-critique pass (2 LLM calls total). Requires `LLM_API_KEY` in `.env`.

**Expected:** a structured explanation for the sample PowerShell/`T1059.001` incident, followed by a line reporting how many chunks were used and whether the self-critique pass flagged any issues.
**Last verified:** 2026-08-16 — ran successfully end-to-end against the real KB (5 chunks retrieved) and Gemini (2 real calls: draft + critique). The self-critique pass **did** flag an issue: it noted the specific host/user/payload values in the draft ("WIN10-ANALYST", "jdoe", "SQBFAFgA...") aren't supported by the retrieved KB chunks — correct, since those are given incident facts, not something a generic MITRE technique doc would ever contain. The `**Confidence check:**` section was appended to the explanation as designed.
**Not re-verified 2026-08-17 (first pass):** same reason as §10.4 — `LLM_API_KEY` is empty in this machine's `.env` today, so the 2 real Gemini calls this step needs were skipped rather than faked. `rag/test_explain_service.py`'s fully-mocked automated tests (§11.1) still cover the pipeline logic offline.

**Re-verified 2026-08-17 (second pass, after a real key was added and §10.4's config.py cwd-resolution bug was fixed):** ran successfully end-to-end against the real KB (5 chunks retrieved) and Gemini (2 real calls: draft + critique). Same known finding as 2026-08-16 — the critique flagged the incident-specific host/user/encoded-command values as unsupported by the KB chunks (correct behavior, not a new bug; see the "Known finding, not a bug" note below), and the `**Confidence check:**` section was appended as designed.

**Known finding, not a bug:** the critique step currently checks *all* claims in the draft against the KB chunks, including incident-specific facts (host, user, command line) that were never meant to come from the KB — they're given directly in the incident context. This makes the critique flag things that are actually fine, which could make the confidence-check section noisy/less useful once real incidents flow through this (Day 10+). Worth revisiting when Day 9 extends the prompt (e.g. scope the critique to only check claims about attacker technique/behavior/response guidance — the parts that should be grounded in retrieved sources — not claims that simply restate the input incident).

---

## 12. Day 7 — Detection engine v1 (Pair 1 deliverable)

### 12.1. Automated tests

```
cd backend
./venv/Scripts/python.exe -m pytest tests/detection/test_rule_loader.py tests/detection/test_engine.py tests/api/test_ingest_detection.py -v
```

Covers `detection/rule_loader.py` (loads + validates `.yml` rules via pySigma, skips malformed files without crashing, module-level cache with `force_reload`), `detection/engine.py` (the `and`/`or`/`not`/parentheses condition parser in isolation, `contains`/`startswith`/`endswith` field modifiers, AND-across-fields-in-one-selection, logsource-category-to-event-ID scoping, and an end-to-end check against the real seed rule in `detection/rules/`), and the `POST /ingest` wiring (`api/test_ingest_detection.py`, monkeypatched rule set + mocked EVTX reader, no DB write path involved).

**Expected:** `20 passed`.
**Last verified:** 2026-08-16 — `20 passed in 8.02s`.
**Note (2026-08-19):** `detection/test_rule_loader.py` was later merged with Day 9's rule-count/tag-parsing tests as part of a `backend/tests/` reorg (see `docs/decisions.md`) — running the command above today collects more than 20 tests as a result. This "20 passed" figure is the historical Day 7-only count; see §16 for the current authoritative full-suite total.
**Re-verified 2026-08-17:** covered as part of the full 90-test regression run directly below — passed.

### 12.2. Full regression pass

```
cd backend
./venv/Scripts/python.exe -m pytest -v
```

**Expected:** `90 passed` (70 from Days 3–8 + 20 new Day 7 detection-engine tests).
**Last verified:** 2026-08-16 — `90 passed in 43.22s`.
**Re-verified 2026-08-17:** `90 passed in 39.85s`, zero failures — full suite unchanged and stable one day later.

### 12.3. Manual smoke test — rule loading (no DB needed)

```
cd backend
./venv/Scripts/python.exe -m app.detection.rule_loader
```

**Expected:** one line per loaded rule (`id  [level]  title  (category=...)`).
**Last verified:** 2026-08-16 —
```
5b1f3a2e-6c1e-4f6a-9b8e-2f8b1a9d6e11  [high]  Suspicious Encoded PowerShell Command  (category=process_creation)
```
**Re-verified 2026-08-17:** identical output — same single seed rule, same ID.

### 12.4. Live server smoke test — `POST /ingest` with detection wired in

```
cd backend
./venv/Scripts/python.exe -m uvicorn app.main:app --port 8000
```
In another shell (from `backend/`):
```
curl -F "file=@../data/sample_logs/sysmon_demo.evtx;type=application/octet-stream" http://127.0.0.1:8000/ingest
```

**Expected without a live Postgres instance (this machine — Docker not installed, same gap as §9.3/§3):** HTTP 500 — `save_events`'s DB commit still fails with `psycopg2.OperationalError: connection ... port 5433 failed: Connection refused` before the newly-added detection step even runs (detection runs after persistence in the route). Not a Day 7 defect — the detection-engine logic itself is fully exercised without a DB dependency by §12.1's automated tests, including the real `/ingest`-route wiring test.
**With Postgres running** (per §3): expect HTTP 200 and a response with the two new fields Day 7 adds to `IngestResponse`:
```json
{"filename":"sysmon_demo.evtx","records_read":4,"events_ingested":4,"events_skipped":0,"rule_matches":0,"matched_rule_titles":[]}
```
`sysmon_demo.evtx`'s 4 records don't contain an encoded-PowerShell process-creation event, so `rule_matches: 0` here is expected — `test_real_seed_rule_matches_encoded_powershell_event` in `detection/test_engine.py` is what proves the seed rule *can* fire, using a crafted matching event.
**Last verified:** 2026-08-16 — reproduced the no-Postgres HTTP 500 exactly as above (traceback confirmed pointing at the same `psycopg2.OperationalError` DB-connect step as §9.3, not at detection code); the Postgres-connected path is confirmed via `api/test_ingest_detection.py`'s SQLite-backed route test instead, since Docker isn't available on this machine.
**Re-verified 2026-08-17 (first pass, before Docker was started):** same HTTP 500 / same `psycopg2.OperationalError` traceback, still ahead of the detection step — no change; see §9.3's matching re-verification for the shared traceback.
**Re-verified 2026-08-17 (second pass, with Postgres up — see §3/§9.3's resolution):** HTTP 200, `{"filename":"sysmon_demo.evtx","records_read":4,"events_ingested":4,"events_skipped":0,"rule_matches":0,"matched_rule_titles":[]}` — matches the "With Postgres running" expectation above exactly, including the two Day 7 detection fields. `rule_matches: 0` is correct — `sysmon_demo.evtx` doesn't contain an encoded-PowerShell event.

> **Day 8 note:** as of Day 8, `IngestResponse` has one more field, `alerts_created` (see §13) — running this exact command today returns the same JSON shape above plus `"alerts_created":0` at the end. §13.4 has the up-to-date example including that field.

### 12.5. Known v1 limitations (by design — see `docs/decisions.md`)
- Condition grammar supports `and`/`or`/`not`/parentheses over bare selection names only — no `1 of`/`all of them` shorthand, no named multi-condition rules.
- Field modifiers: exact match (case-insensitive), `contains`, `startswith`, `endswith` only — no `|re` or glob `*` wildcards yet.
- Only one seed rule exists in `detection/rules/` (`suspicious_encoded_powershell.yml`) — **resolved in Day 8** (§13): now 5 rules across process-creation/network-connection/file-creation categories, with `alerts` persistence wired in.

### 12.6. Prep task — real Sysmon Event ID 3 capture from a clean VM (manual, not run here)

The dev laptop's McAfee firewall blocks Sysmon's network-monitoring driver (§7.2), so a real network-connection (Event ID 3) sample still needs to come from a clean VM/sandbox. This is a hands-on task for whoever has VM access — not something automatable from this repo:

1. Spin up a clean Windows VM/sandbox with no conflicting AV/firewall product.
2. Download Sysinternals `Sysmon64.exe` + a minimal config covering ProcessCreate (ID 1), NetworkConnect (ID 3), FileCreate (ID 11) — `sysmon64.exe -i minimal-config.xml`.
3. Generate a real outbound network connection from a monitored process (e.g. `curl`/`Invoke-WebRequest` to any external host).
4. Export the relevant `Microsoft-Windows-Sysmon/Operational` log to `.evtx` (Event Viewer → right-click the log → "Save All Events As...").
5. Copy the exported file into `data/sample_logs/sysmon_vm_capture.evtx` on the dev machine and commit it (`docs: real sysmon event id 3 sample from clean vm`).

**Status:** done — `data/sample_logs/sysmon_vm_capture.evtx` (63MB) captured from a clean VM (`Computer=Nightowl`, 2026-08-16). Verified by running it through the real pipeline at three levels, not just counting event IDs:
- **Raw read** (`evtx_reader.read_records_as_dicts`): 64,558 records, 0 read errors.
- **Normalize + detect** (`normalizer.normalize_event` → `detection.engine.evaluate_event`): 0 normalize errors across all 64,558 records. Event-ID breakdown: `FileCreate(11): 64413, ProcessCreate(1): 26, ProcessTerminate(5): 19, NetworkConnect(3): 100` — 100 genuine Event ID 3 records present, with real fields (`Image`, `Protocol`, `SourceIp`, `DestinationIp`, ports). 0 rule matches, expected — the only seed rule targets encoded-PowerShell process creation, not present in this capture.
- **Full `POST /ingest` route** (`TestClient` + in-memory SQLite, same pattern as §12.4/`api/test_ingest_detection.py`): HTTP 200, `records_read: 64558, events_ingested: 64558, events_skipped: 0, rule_matches: 0` — the entire real-world file flows through read → normalize → persist → detect without a single dropped record.

Not wired into pytest as a hard dependency (same rationale as §12's other real-file checks — a machine-specific real file shouldn't be a hard dependency of the automated suite); this was a manual verification pass. The Day 8 network-connection-category Sigma rule can be developed/tested against this real fixture instead of only hand-crafted ones.

---

## 13. Day 8 — 5 Sigma rules + alert persistence (Pair 1 deliverable)

Builds directly on §12's detection engine v1: the rule set grows from the single Day 7 seed rule
to 5 rules covering all 3 categories the engine supports, and every match is now persisted as an
`alerts` row (`app/models/alert.py`, already-migrated `alerts` table) instead of only being counted
in the `POST /ingest` response.

**The 5 rules** (`app/detection/rules/*.yml`):

| Title | Category | Technique | Level |
|---|---|---|---|
| Suspicious Encoded PowerShell Command (Day 7 seed) | process_creation | T1059.001 | high |
| Certutil Download via urlcache/split Flags | process_creation | T1105 | high |
| PowerShell Execution Policy Bypass | process_creation | T1059.001 | medium |
| Suspicious Network Connection from LOLBin | network_connection | T1071.001 | medium |
| Suspicious Executable Written to Public or Temp Directory | file_event | T1105 | medium |

All 5 stay within the engine's existing v1 grammar (§12.5's limitations still apply — no `|re`,
no `1 of`, etc.) and match against real Sysmon field names, matching the Day 7 decision recorded in
`docs/decisions.md`.

**New module:** `app/services/detection_service.py` — `create_alert`/`save_alerts`, mirroring
`event_service.py`'s create/save shape. `Alert.severity` is a direct pass-through of the rule's
`level` string (no enum/translation table — the column has no constraint requiring one).
`POST /ingest`'s `IngestResponse` gains a new `alerts_created: int` field alongside the existing
`rule_matches`/`matched_rule_titles` (both unchanged, so this is additive, not breaking).

### 13.1. Automated tests

```
cd backend
./venv/Scripts/python.exe -m pytest tests/services/test_detection_service.py tests/api/test_ingest_alerts.py -v
```

Covers:
- `services/test_detection_service.py` — in-memory SQLite: `create_alert`/`save_alerts` persist the
  `event_id` FK, `rule_id`, severity pass-through, and `matched_at`; batch commit; empty-list no-op;
  round-trip query. (SQLite drops tzinfo on read-back, unlike Postgres — the one test that checks
  `matched_at` compares tolerantly for that reason; not an app-level concern.)
- `api/test_ingest_alerts.py` — extends `api/test_ingest_detection.py`'s `TestClient` +
  in-memory-SQLite pattern: a matching event now produces both `alerts_created: 1` in the response
  *and* a real `Alert` row queryable from the same session, with the correct FK to the persisted
  `Event` row; multiple matching events in one upload produce multiple alert rows; benign events
  produce zero.

**Expected:** `18 passed` (as originally verified — see note below for the current command's count).
**Last verified:** 2026-08-18 — `18 passed in ~1.5s`.

**Note (2026-08-19):** the original command above also ran a third file, `test_day8_detection_rules.py`
(rule-fire/no-fire checks for the 4 new rules — 10 tests), which was deleted during a `backend/tests/`
reorg once confirmed to be a strict subset of `detection/test_rules_matrix.py`'s full 10-rule fire/
no-fire matrix (see `docs/decisions.md`). Running the updated command above today collects 8 tests,
not 18 — the missing 10 are still covered, just in `detection/test_rules_matrix.py` (§15.1) instead.

Two existing Day 6 tests (`test_ingest_sysmon_demo_happy_path`,
`test_ingest_skips_malformed_records_and_ingests_the_rest` in `api/test_ingest_route.py`) hardcode
the full `IngestResponse` JSON shape and needed one line added (`"alerts_created": 0`) for the new
field — both still pass, this was an expected, mechanical update, not a behavior change.

### 13.2. Full regression pass

```
cd backend
./venv/Scripts/python.exe -m pytest -v
```

**Expected:** `108 passed` (90 from Days 3–8/Day 7 detection engine + 18 new Day 8 tests).
**Last verified:** 2026-08-18 — `108 passed in 25.78s`.

### 13.3. Manual smoke test — rule loading (no DB needed)

```
cd backend
./venv/Scripts/python.exe -m app.detection.rule_loader
```

**Expected:** 5 lines, one per rule, covering all 3 categories.
**Last verified:** 2026-08-18 —
```
8c2e5f11-4a3b-4d7e-9c1a-6b5e2f8a7d33  [high]  Certutil Download via urlcache/split Flags  (category=process_creation)
1d9a4e7c-2f6b-4c8a-b3d1-7e9c5a2f4b16  [medium]  PowerShell Execution Policy Bypass  (category=process_creation)
5b1f3a2e-6c1e-4f6a-9b8e-2f8b1a9d6e11  [high]  Suspicious Encoded PowerShell Command  (category=process_creation)
6f3b8d21-9a1c-4e5f-8b2d-3c7a1e9f5d84  [medium]  Suspicious Executable Written to Public or Temp Directory  (category=file_event)
2a7e9c14-5d3f-4b6a-9e1c-8f4a2d7b6c53  [medium]  Suspicious Network Connection from LOLBin  (category=network_connection)
```

### 13.4. Live server smoke test — real alert persisted against real Postgres

```
cd backend
./venv/Scripts/python.exe -m uvicorn app.main:app --port 8000
```

`sysmon_demo.evtx` (§9.3's fixture) still doesn't contain a matching event for any of the 5 rules,
so posting it produces `alerts_created: 0` — same non-defect as §12.4. To prove alert persistence
against a *real* HTTP request and the *real* Postgres database (not the test suite's SQLite
override), a `TestClient`-driven script posted one crafted encoded-PowerShell record through the
actual running `app.main:app` (only `read_records_as_dicts` monkeypatched to yield the record;
everything else -- routing, detection, DB session, real `DATABASE_URL` -- is the real thing):

```json
{"filename":"live_demo.evtx","records_read":1,"events_ingested":1,"events_skipped":0,"rule_matches":1,"matched_rule_titles":["Suspicious Encoded PowerShell Command"],"alerts_created":1}
```

Confirmed via `docker compose exec db psql -U nightowl -d nightowl -c "SELECT id, event_id, rule_id, severity, matched_at FROM alerts ORDER BY id;"`:
```
 id | event_id |               rule_id                | severity |          matched_at
----+----------+---------------------------------------+----------+-------------------------------
  1 |       18 | 5b1f3a2e-6c1e-4f6a-9b8e-2f8b1a9d6e11  | high     | 2026-08-17 03:32:31.934447+00
```
`rule_id` matches the real seed rule's UUID, `severity` matches its `level`, and `event_id` (18)
correctly points at the just-persisted `Event` row from the same request, not the raw Sysmon Event
ID (1).
**Last verified:** 2026-08-18.

### 13.5. Real-data check — do the new rules fire against `sysmon_vm_capture.evtx`?

Ran all 5 rules against the full 64,558-record real VM capture (§12.6) via
`evtx_reader`→`normalizer`→`rule_loader`→`engine.evaluate_event`, same read-only pattern as §12.6's
verification (not wired into pytest, machine-specific real file).

**NetworkConnect(3) breakdown (100 records):** all are `svchost.exe` (93, SSDP/mDNS/LLMNR
background chatter), `msedge.exe` (5), `explorer.exe` (1), and Windows Defender's
`MpDefenderCoreService.exe` (1) — no LOLBin (`powershell.exe`/`certutil.exe`/`curl.exe`) network
activity anywhere in this capture, so the new "Suspicious Network Connection from LOLBin" rule
correctly does **not** fire against it. This is expected, benign VM background traffic, not a gap
in the rule — it's verified to fire against a crafted event instead (§13.1).
**Last verified:** 2026-08-18 — ran all 5 rules against all 64,558 records: `total matches: 0` across the board (process_creation, network_connection, and file_event alike) — this clean VM capture contains no malicious activity by design (§7.2/§12.6's capture process only generated harmless `whoami`/`curl`/temp-file actions plus normal OS background chatter), so zero matches across a real, large, mixed-category file is the correct result, not a rule defect. Each rule's ability to fire is separately proven with crafted matching events in §13.1/§13.3.

### 13.6. Known v1 limitations carried forward from §12.5

Same grammar limitations as Day 7 (no `|re`/glob, no `1 of`/`all of`, category-scoped to
process_creation/network_connection/file_event only) — none of the 4 new rules needed anything
outside this grammar. The `rules` DB table (`app/models/rule.py`) is still never populated by
`rule_loader.py` (it only produces in-memory `LoadedRule` objects) — out of scope for Day 8 per the
roadmap, worth flagging for whenever a Day 16 "rules manager" UI needs enable/disable state backed
by the DB rather than the filesystem.

---

## 14. Day 9 — 10 rules + incident grouping (Pair 1 deliverable)

Builds directly on §13's detection engine: the rule set grows from 5 to 10, adding a 4th category
(`registry_event`, Sysmon Event ID 13 — Value Set only, see `docs/decisions.md`), and every match
is now grouped into an `Incident` (same host + a 1-hour window reuses the most recent open
incident) rather than staying as a bare, ungrouped alert.

**The 5 new rules** (`app/detection/rules/*.yml`):

| Title | Category | Technique | Level |
|---|---|---|---|
| Registry Run Key Persistence | registry_event | T1547.001 | medium |
| Registry IFEO Debugger Hijack | registry_event | T1546.012 | high |
| Scheduled Task Creation via schtasks.exe | process_creation | T1053.005 | medium |
| Suspicious Scheduled Task via PowerShell Cmdlet | process_creation | T1053.005 | medium |
| Suspicious Mshta Execution | process_creation | T1218.005 | high |

("Scheduled task" rules stay in `process_creation` rather than a dedicated logsource — see
`docs/decisions.md` for why.)

**`rule_loader.py`** now also parses `technique_id`/`tactics` out of each rule's own `tags:` list
(e.g. `attack.t1547.001` → technique id, `attack.persistence` → tactic) — tag *extraction*, not
MITRE-dataset validation (that stays Day 11's job). **New `app/services/incident_service.py`** —
`find_or_create_incident(db, host, matched_at, match)`, mirroring `event_service.py`/
`detection_service.py`'s create/save layering. **Schema change:** `incidents` gained a `host`
column, `alerts` gained a nullable `incident_id` FK (migration `6b1a55c7f800`). `POST /ingest`'s
`IngestResponse` gained `incident_ids: list[int]`.

### 14.1. Automated tests

```
cd backend
./venv/Scripts/python.exe -m pytest tests/detection/test_rule_loader.py tests/services/test_incident_service.py tests/api/test_ingest_incidents.py -v
```

Covers:
- rule-count/category/tag-parsing tests (now merged into `detection/test_rule_loader.py`, see the
  §12.1 note) — 10 rules load, all 4 categories present, every rule's `technique_id`/`tactics`
  parse correctly from its own tags.
- `services/test_incident_service.py` — `find_or_create_incident`: same host+window merges into one
  incident (technique ids accumulate without duplicates, severity bumps to the higher of the two);
  different host, or outside the window, creates a separate incident; a closed incident is never
  reused.
- `api/test_ingest_incidents.py` — extends `api/test_ingest_alerts.py`'s `TestClient`+SQLite
  pattern: two matching alerts on the same host in one upload link to the same incident with both
  technique ids; different hosts get separate incidents; benign events create none.

Two existing tests needed mechanical updates for the shape changes (same pattern as Day 8's Day 6
updates): `api/test_ingest_route.py`'s two full-response-dict assertions gained
`"incident_ids": []`, and `services/test_detection_service.py`'s `save_alerts(...)` calls gained a 4th
tuple element (`incident_id`, `None` in those tests). Also, the old `test_day8_detection_rules.py`'s
two exact-count assertions (`== 5 rules`, `== {3 categories}`) were loosened to lower-bound checks
(`>= 5`, subset) since Day 9 legitimately grows both — that file was later deleted entirely once its
remaining coverage became a strict subset of `detection/test_rules_matrix.py` (§15.1/§13.1's note);
the exact current rule-count/category totals live in `detection/test_rule_loader.py`.

**Note (2026-08-19):** file paths above updated for the `backend/tests/` reorg (`docs/decisions.md`);
`detection/test_rule_loader.py` now also contains Day 7's rule-loading tests, so this command's
current test count is higher than what was originally verified for "Day 9's own tests" alone.

**Expected:** `17 passed` (7 + 7 + 3).
**Last verified:** 2026-08-19 — `17 passed`.

### 14.2. Full regression pass

```
cd backend
./venv/Scripts/python.exe -m pytest -v
```

**Expected:** `155 passed` as originally verified 2026-08-19 (108 through Day 8 + 17 new Day 9 tests + 30 new Day 10 tests, see §15). **Superseded same day** by the `backend/tests/` reorg (`docs/decisions.md`), which deleted 10 tests confirmed fully redundant with `detection/test_rules_matrix.py` — current expected total is `145 passed`, see §16.2.
**Last verified:** 2026-08-19 — `155 passed in 45.80s`.

### 14.3. Manual smoke test — rule loading (no DB needed)

```
cd backend
./venv/Scripts/python.exe -m app.detection.rule_loader
```

**Expected:** 10 lines across 4 categories (`process_creation` ×6, `registry_event` ×2,
`network_connection` ×1, `file_event` ×1).
**Last verified:** 2026-08-19 — all 10 rules printed, categories as expected.

### 14.4. Live server smoke test — incident grouping against real Postgres

A `TestClient`-driven script (same technique as §13.4) posted two crafted process-creation events
on the same host (`DEMO-HOST-D9`) — one matching the encoded-PowerShell rule, one matching the new
schtasks.exe rule — through the real running app and real Postgres:

```json
{"filename":"live_demo_day9.evtx","records_read":2,"events_ingested":2,"events_skipped":0,"rule_matches":2,"matched_rule_titles":["Suspicious Encoded PowerShell Command","Scheduled Task Creation via schtasks.exe"],"alerts_created":2,"incident_ids":[1]}
```

Both alerts grouped into **one** incident (`incident_ids: [1]`), confirmed via
`docker compose exec db psql -U nightowl -d nightowl -c "SELECT id, title, severity, mitre_technique_ids, host FROM incidents ORDER BY id DESC LIMIT 3;"`:
```
 id |                         title                         | status | severity |    mitre_technique_ids     |     host
----+-------------------------------------------------------+--------+----------+----------------------------+--------------
  1 | Suspicious Encoded PowerShell Command on DEMO-HOST-D9 | open   | critical | ["T1059.001", "T1053.005"] | DEMO-HOST-D9
```
`mitre_technique_ids` correctly accumulated both techniques; `severity` shows `critical` — see
§15.4 for why (Day 10's severity scoring landed in the same session and is visible in this same
result).
**Last verified:** 2026-08-19.

### 14.5. Known v1 limitations

- Registry detection covers Sysmon Event ID 13 (Value Set) only, not 12 (create/delete) or 14
  (rename) — see `docs/decisions.md`.
- Grouping window is a fixed 1 hour, same-host-only — no cross-host correlation, no configurable
  window yet.
- The `rules` DB table is still never populated (same gap noted in §13.6) — still deferred, not a
  Day 9 blocker.

---

## 15. Day 10 — Severity scoring + unit tests (Pair 1 deliverable)

Combines each matched rule's base Sigma `level` with a weight for the MITRE tactic(s) it's tagged
with (parsed from `tags:` in Day 9), so the final alert/incident severity reflects real attacker
progress, not just the rule author's raw level. See `docs/decisions.md` for the full formula and
reasoning.

**New `app/services/severity_service.py`** — `compute_severity(base_level, tactics) -> str` and
`higher_severity(a, b) -> str` (used by `incident_service.py` when merging). `engine.evaluate_event`
now calls `compute_severity` when building each `RuleMatch`, so `RuleMatch.level` (and therefore
`Alert.severity`) is the final weighted value everywhere downstream — no other call site needed to
change, since existing tests with no tactics see weight 0 (unchanged behavior).

### 15.1. Automated tests

```
cd backend
./venv/Scripts/python.exe -m pytest tests/detection/test_severity_service.py tests/detection/test_rules_matrix.py -v
```

Covers:
- `detection/test_severity_service.py` — no tactics leaves the base level unchanged; a single low-weight
  tactic bumps by one rank; a high-weight tactic (e.g. `impact`) bumps and caps at `critical`;
  multiple tactics use only the highest weight; an already-`critical` base stays capped; unknown
  levels default to medium's rank; unknown tactics contribute zero weight; `higher_severity` picks
  the higher-ranked label (or either, on a tie).
- `detection/test_rules_matrix.py` (**originally `test_detection.py`, the exact filename from the
  roadmap's Day 10 Files column — moved during the `backend/tests/` reorg for structural
  consistency, an acknowledged deviation recorded in `docs/decisions.md`**) — the full fire/no-fire
  matrix for all 10 rules: a data-driven `@pytest.mark.parametrize` table of (matching event, benign
  look-alike) pairs per rule, asserting every rule fires on its matching event and does *not*
  false-positive on the look-alike, plus one check that the matrix itself covers exactly the 10 real
  rule titles (so a future rule addition without a matching test case fails loudly).

**Expected:** `30 passed` (9 + 21).
**Last verified:** 2026-08-19 — `30 passed`.

### 15.2. Full regression pass

Same command as §16.2 (full `pytest -v`) — Day 9 and Day 10 landed together in this session;
current expected total is `145 passed`, see §16.2's note on the same-day reorg.

### 15.3. Manual smoke test — severity formula

```
cd backend
./venv/Scripts/python.exe -c "
from app.services.severity_service import compute_severity
print(compute_severity('high', ['execution']))
print(compute_severity('medium', ['impact']))
print(compute_severity('low', []))
"
```
**Expected:** `critical` (4+1=5), `critical` (3+3=6, capped at 5), `low` (no tactics, unchanged).
**Last verified:** 2026-08-19 — exactly as expected.

### 15.4. Live verification — visible in §14.4's real Postgres result

§14.4's live demo already shows this working end to end: the seed rule (`level: high`, tagged
`attack.execution`) produced an `Alert`/incident `severity` of `critical` (high=4 + execution
weight 1 = 5), not `high` as it would have shown under Day 8's plain pass-through — a real,
intentional, visible behavior change from one day to the next, not a regression.

### 15.5. Known v1 limitations

- Tactic weights are a small hand-picked table (`docs/decisions.md`), not derived from any formal
  MITRE scoring methodology — reasonable defaults, not a calibrated risk model.
- Severity is computed per-match at evaluation time; it is not recomputed retroactively if a rule's
  tags are edited after alerts already exist for it.

---

## 16. Full Repository Manual Test Runbook (consolidated, run everything)

Everything above (§1–§12) is a detailed, day-by-day reference — what each piece covers, why, and
its full verification history. This section is the opposite: a single linear checklist to run the
**whole repo** end-to-end in one sitting, e.g. before a demo or a milestone check-in. It doesn't
re-explain anything — it just sequences the commands and points back to the section with the full
detail/expected output for each step.

### 16.1. Prerequisites checklist

- [ ] `backend/venv` exists with deps installed (§0). If not: `cd backend && python -m venv venv && ./venv/Scripts/pip install -r requirements.txt` (see §0 for the two Windows install gotchas).
- [ ] Repo-root `.env` exists (`cp .env.example .env` if not).
- [ ] *Optional, for §16.3's Postgres block:* Docker Desktop installed and running (`docker info` succeeds).
- [ ] *Optional, for §16.3's live-LLM block:* `LLM_API_KEY` set in `.env` (free key: https://aistudio.google.com/apikey).

Everything in §16.2 runs with **just the first two boxes checked**. §16.3 is gated on Docker/API key and is explicitly optional/skippable.

### 16.2. Core pass — no Docker, no API key required

Run top to bottom from the repo root unless noted:

```
cd backend

# 1. Full automated suite — everything Pair 1 + Pair 2 have built so far
./venv/Scripts/python.exe -m pytest -v
# Expect: 169 passed (see §19.3 for Day 12's confirmation; §14.2/§15.2 for the Day 9/10
#         running total this grew from, and their notes on the same-day backend/tests/ reorg)

# 2. Start the API server in one shell, then run the rest from a second shell
./venv/Scripts/python.exe -m uvicorn app.main:app --port 8000
```

In a second shell (from `backend/`, so relative sample-log paths resolve):
```
# 3. Health check
curl http://127.0.0.1:8000/health
# Expect: {"status":"ok"}                                          (§4)

# 4. MITRE techniques endpoint (no DB dependency)
curl http://127.0.0.1:8000/mitre/techniques
# Expect: HTTP 200, {"techniques":[...],"count":858}, sorted by ID  (§9.4)

# 5. Ingest happy path (sysmon_demo.evtx fixture)
curl -F "file=@../data/sample_logs/sysmon_demo.evtx;type=application/octet-stream" http://127.0.0.1:8000/ingest
# Expect: HTTP 200 + rule_matches/matched_rule_titles/incident_ids fields WITH Postgres running (§3, §16.3)
# Expect: HTTP 500 (psycopg2 "port 5433 ... Connection refused") WITHOUT Postgres — a known,
#         non-defect gap, not a new bug. The same request path is separately proven correct
#         end-to-end against SQLite by the automated suite in step 1.               (§9.3/§12.4)

# 6. Ingest error handling — three cases, all pure validation, no DB touched
curl -F "file=@<a-non-evtx-file>;type=text/plain" http://127.0.0.1:8000/ingest
curl -F "file=@<a-0-byte-file>;type=application/octet-stream" http://127.0.0.1:8000/ingest
curl -F "file=@<a-file-with-garbage-bytes>;type=application/octet-stream" http://127.0.0.1:8000/ingest
# Expect: all three HTTP 400, with the three specific `detail` messages in §9.3

# 7. Incident list + detail endpoints (Day 12)
curl http://127.0.0.1:8000/incidents
# Expect: HTTP 200 + {"incidents":[...],"count":N} WITH Postgres running (§19.7)
# Expect: HTTP 500 {"detail":"internal server error"} WITHOUT Postgres — the new consistent
#         JSON error handler (§19.6), not a raw traceback like pre-Day-12 unhandled errors

curl http://127.0.0.1:8000/incidents/999999
# Expect: HTTP 404, {"detail":"incident 999999 not found"} WITH Postgres running (§19.7)
```

Back in the first shell, stop the server (Ctrl+C), then run the two no-server, no-key module smoke tests:
```
cd backend
./venv/Scripts/python.exe -m app.detection.rule_loader
# Expect: 15 lines across 4 categories (id, level, title, category)                (§19.4)

./venv/Scripts/python.exe -m app.rag.prompts
# Expect: rendered system message (grounding rules) + human message (sample incident + 1 chunk)  (§10.3)
```

### 16.3. Optional extended pass — needs Docker and/or an LLM API key

Only run the parts your environment supports:

```
# Needs Docker Desktop running:
docker compose up -d db                        # §3
docker compose exec db pg_isready -U nightowl
cd backend
./venv/Scripts/python.exe -m alembic upgrade head
./venv/Scripts/python.exe -m alembic current    # Expect: fa0ac08ab62f (head)
docker compose exec db psql -U nightowl -d nightowl -c "\dt"   # Expect: 6 tables

# With Postgres now up, re-run step 5 of §16.2 — expect HTTP 200 this time instead of 500.
# Also re-run step 7 (GET /incidents, GET /incidents/999999) — expect HTTP 200/404 instead
# of the no-Postgres HTTP 500, and GET /incidents/<a real id from step 5's response> for the
# full detail view (alerts + events + resolved MITRE techniques).                   (§19.7)

# Needs LLM_API_KEY set in .env:
./venv/Scripts/python.exe -m app.rag.llm_client       # real Gemini call, §10.4
./venv/Scripts/python.exe -m app.rag.explain_service  # real retrieve + 2 Gemini calls, §11.3
```

### 16.4. Sign-off checklist

| Component | Section | Result | Notes |
|---|---|---|---|
| Full pytest suite (169 tests) | §19.3 | ☐ Pass ☐ Fail | |
| Alert persistence on rule match | §13.1/§13.4 | ☐ Pass ☐ Fail | |
| Incident grouping (same host+window) | §14.1/§14.4 | ☐ Pass ☐ Fail | |
| Severity scoring (base level + tactic weight) | §15.1/§15.4 | ☐ Pass ☐ Fail | |
| MITRE technique validation (warn-only) | §18 | ☐ Pass ☐ Fail | |
| `/health` | §4 | ☐ Pass ☐ Fail | |
| `GET /mitre/techniques` | §9.4 | ☐ Pass ☐ Fail | |
| `POST /ingest` happy path | §9.3/§12.4 | ☐ Pass ☐ Fail ☐ Skipped (no Docker) | HTTP 500 without Postgres is expected, not a fail |
| `POST /ingest` error cases (×3) | §9.3 | ☐ Pass ☐ Fail | |
| `rule_loader` module smoke (15 rules) | §19.4 | ☐ Pass ☐ Fail | |
| `prompts` module smoke | §10.3 | ☐ Pass ☐ Fail | |
| `GET /incidents` (+ filters) | §19.7 | ☐ Pass ☐ Fail ☐ Skipped (no Docker) | HTTP 500 without Postgres is expected (§19.6), not a fail |
| `GET /incidents/{id}` (alerts+events+techniques) | §19.7 | ☐ Pass ☐ Fail ☐ Skipped (no Docker) | |
| `GET /incidents/{id}` 404 case | §19.6/§19.7 | ☐ Pass ☐ Fail | |
| Structured JSON logging | §19.5 | ☐ Pass ☐ Fail | |
| Consistent JSON error handling (500s) | §19.6 | ☐ Pass ☐ Fail | |
| `tests/test_ingest_flow.py` e2e (real rules, real MITRE lookup) | §19.2 | ☐ Pass ☐ Fail | |
| Postman collection walkthrough (all endpoints) | §21 | ☐ Pass ☐ Fail | |
| Postgres/Alembic (6 tables) | §3 | ☐ Pass ☐ Fail ☐ Skipped (no Docker) | |
| Live Gemini call (`llm_client`) | §10.4 | ☐ Pass ☐ Fail ☐ Skipped (no API key) | |
| Live explain_service (2 Gemini calls) | §11.3 | ☐ Pass ☐ Fail ☐ Skipped (no API key) | |
| Real Sysmon VM capture through full pipeline | §12.6/§13.5 | ☐ Pass ☐ Fail ☐ Not re-run (63MB file, manual only) | |

Tester: ____________  Date: ____________  Environment (Docker? API key?): ____________

**Scope reminder** (matches "Out of scope" below): this runbook covers everything built through Pair 1 Day 12 (15 detection rules, incident grouping, severity scoring, MITRE technique validation, `GET /incidents`/`GET /incidents/{id}`, consistent error handling, structured JSON logging, e2e integration test — **Milestone: Backend + Detection core complete**) and Pair 2 Day 8 (explain_service). It does **not** cover Pair 2's Day 9–12 (explain endpoint with source attribution, hallucination spot-check, chat endpoints, LLM robustness — teammates' own work, not covered by this session), the frontend (none built yet), or the formal Testing Report — those are still ahead on the roadmap.

**2026-08-17 run of this exact checklist:** §16.2's entire core pass executed for real — 90/90 tests passed (39.85s), `/health` 200, `/mitre/techniques` 200 (count 858), all 3 ingest error cases HTTP 400 as expected, `rule_loader` and `prompts` module smoke tests both matched their documented output exactly. Ingest happy path initially returned HTTP 500 (Docker Desktop wasn't running yet — same known gap as prior days); §16.3's Docker block was then run for real (Docker Desktop started, `docker compose up -d db`, `alembic upgrade head` → `fa0ac08ab62f (head)`, 6 tables confirmed), after which the happy path returned HTTP 200 as designed — see §3/§9.3/§12.4's "second pass" notes.

**2026-08-19 update:** Pair 1's Day 9 (10 rules, incident grouping) and Day 10 (severity scoring, `detection/test_rules_matrix.py`, originally `test_detection.py`) landed in one session — full suite reached `155 passed`, live-verified against the same real Postgres instance (§14.4). Pair 2's Day 9/10 (explain endpoint, hallucination spot-check) intentionally not covered here — that's the teammates' own work.

**2026-08-19, later same day — `backend/tests/` reorg:** user requested cleaning up the test suite structure (24 files, all flat and `test_dayN_*`-named, didn't mirror `backend/app/`'s package layout). Reorganized into subpackages (`api/`, `detection/`, `services/`, `ingestion/`, `mitre/`, `rag/`) matching `app/`'s layout, dropped all `dayN` prefixes, added a shared `conftest.py` fixture (`api_client`) removing duplicated `TestClient`+SQLite boilerplate from 4 files, and merged/deleted a few files with confirmed-redundant or combinable coverage (see `docs/decisions.md`). Full suite re-verified after every step: **`145 passed`** (155 − 10 intentionally-removed redundant tests, zero coverage lost). See §16.2 for the current command.

A real Gemini key was then added to `.env`, which surfaced one genuine bug (not environmental): `app/core/config.py`'s `Settings` resolved `.env` relative to the process's cwd, but every command here runs from `backend/`, so the key was never actually read regardless of what was in the file. Fixed in `config.py` (resolve `.env` from the module's own file location instead of cwd) — full 90-test suite re-confirmed green after the fix, then both live-Gemini checks (§10.4, §11.3) ran for real and succeeded. **As of 2026-08-17, every check in this runbook has been executed for real and passes** — no known gaps remain except Docker Desktop needing a manual start each session (it doesn't auto-launch on this machine).

**2026-08-19 update — Day 11/12 landed, guide extended through Day 12, Postman collection added:** Pair 1's Day 11 (MITRE technique validation, warn-only) and Day 12 (`GET /incidents`/`GET /incidents/{id}`, 5 more rules — 15 total — consistent JSON error handling, structured JSON logging, `tests/test_ingest_flow.py`) are covered in the new §18/§19 below — **Milestone: Backend + Detection core complete**. Full suite re-verified for real this session: `169 passed in 14.58s` (up from 145 — see §19.3). The no-Postgres path was verified for real first: `GET /incidents` and `POST /ingest` both returned a clean `HTTP 500 {"detail":"internal server error"}` (§19.6), confirming the new `core/errors.py` handler works, replacing what used to be a raw, unhandled traceback. Docker Desktop was then started and §19.7's full live-Postgres flow was also completed for real the same day: `docker compose up -d db`, `alembic upgrade head` (`6b1a55c7f800 (head)`), then the real `GET /incidents`/`GET /incidents/{id}`/severity-filter/404 flow against a real incident persisted in the Docker volume from an earlier session — every read path confirmed working end to end, no gaps left open in §19. A new §20 documents a real, importable Postman collection (`docs/postman/NightOwl.postman_collection.json` + `.postman_environment.json`) covering every endpoint through Day 12 — added specifically so the multipart `/ingest` upload no longer needs this environment's git-bash `curl` workaround (see the Troubleshooting table).

---

## 17. Day 9 — Explain endpoint with source attribution (Pair 2 deliverable)

Pair 1's incident grouping (§14, `services/incident_service.py`) landed since this was last verified, so real `Incident` rows now exist in principle — but Docker/Postgres aren't available in this environment (see Troubleshooting), so this section still verifies against manually-inserted rows via an in-memory SQLite substitution, same posture as `explain_service.py` (§11) itself.

### 17.1. Automated tests

```
cd backend
./venv/Scripts/python.exe -m pytest tests/api/test_incidents_route.py tests/rag/test_prompts.py -v
```

Covers `api/routes_incidents.py`'s `POST /incidents/{incident_id}/explain`: 404s with the incident id in the message when it doesn't exist; on a real `Incident` row, calls `explain_service.generate_explanation()` (mocked) and returns `explanation` (full text, unchanged from Day 8), `recommended_response` (the `## Recommended next steps` section extracted via the new `prompts.extract_recommended_response()`), and `sources` (the retrieved chunks + similarity scores, unchanged shape from `retriever.retrieve()`). Also covers `extract_recommended_response()` directly: text after the heading, or `""` when the heading is missing or the input is empty. Fully offline — `generate_explanation` is mocked, no network call, no real API key used.

**Expected:** `15 passed` (3 from `test_incidents_route.py` + 12 from `test_prompts.py`, which grew from 9 to 12 with the new `extract_recommended_response` cases).
**Last verified:** 2026-08-18 — `15 passed in 13.11s`, both files rewritten during this rebase to fit Pair 1's same-day `backend/tests/` reorg (§16): `test_day9_explain_route.py` moved to `tests/api/test_incidents_route.py` and rewritten against the shared `api_client` fixture (`conftest.py`); the `extract_recommended_response` cases landed directly in `tests/rag/test_prompts.py` (git's rename detection carried them through the `test_day7_prompts.py` → `tests/rag/test_prompts.py` move automatically).

### 17.2. Full regression pass

```
cd backend
./venv/Scripts/python.exe -m pytest -v
```

**Expected:** `76 passed` against the pre-rebase Day 3–9 base (70 from Day 3–8 + 6 new: 3 route tests + 3 `extract_recommended_response` tests) — this was the count verified before rebasing onto Pair 1's Day 9/10 work; see §16.2 for the combined total after rebase.
**Last verified:** 2026-08-18 — `76 passed in 34.86s`.

> **Note on this venv:** the very first run after this session's changes hit `ModuleNotFoundError: Could not import module 'PreTrainedModel'` from inside `sentence_transformers` during collection (7 files errored). Re-running immediately after — with no changes — passed cleanly (`76 passed`), and `transformers`/`sentence_transformers` import fine standalone (`python -c "from sentence_transformers import SentenceTransformer"`). Looks like a transient cold-start issue in this venv (first heavy-import pass under pytest's collector), not a real incompatibility — `sentence-transformers==5.7.0`'s declared range (`transformers<6.0.0,>=4.41.0`) is satisfied by the installed `transformers==5.15.0`. Flagging in case it recurs: if a *fresh* venv reproduces this reliably (not just a one-off), it needs a real fix (pin a narrower `transformers` version in `requirements.txt`), not just a re-run.

### 17.3. Manual end-to-end smoke test — real Incident row + real Gemini call

Docker isn't installed in this environment (see Troubleshooting table), so this substitutes an in-memory SQLite DB for Postgres via the same `dependency_overrides[get_db]` pattern the automated route tests use — it exercises the real route code (`routes_incidents.py`'s incident lookup, `_incident_to_dict`, response building) end-to-end with *unmocked* `generate_explanation`, i.e. a real Chroma retrieval + two real Gemini calls (draft + self-critique), just without a real Postgres-backed `Incident` row. Requires a real `LLM_API_KEY` in `.env` (`backend/.env`, gitignored — not `.env.example`; the key previously found pasted into the tracked `.env.example` was treated as compromised and never reused here).

```
cd backend
./venv/Scripts/python.exe scripts/smoke_test_explain_route.py
```

(ad hoc script: builds a `TestClient(app)` against an in-memory SQLite engine, inserts one `Incident` row — title "Suspicious PowerShell execution on WIN10-ANALYST", severity "high", `mitre_technique_ids=["T1059.001"]` — then `POST`s `/incidents/{id}/explain` and prints the JSON response.)

**Expected:** HTTP 200 with a non-empty `explanation` (the same three-section structure as §10.4/§11.3), a `recommended_response` matching the `## Recommended next steps` section of that explanation, and a `sources` list of retrieved KB chunks with `score` fields.
**Last verified:** 2026-08-18 — HTTP 200. Retrieved 5 real chunks (3 from the `T1059_001_powershell_execution` playbook, 2 from the MITRE `T1059.001` technique doc, scores 0.45–0.56). `explanation` came back correctly structured (What happened / Why it matters / Recommended next steps + a `**Confidence check:**` section). `recommended_response` correctly matched just the "Recommended next steps" text, split out via `extract_recommended_response()`. `sources` contained all 5 chunks with `chunk_id`/`document`/`metadata`/`score`.

Same known finding as §11.3 recurred here (expected — Day 9 deliberately didn't touch critique scoping): the self-critique flagged the claim that the alert occurred on "WIN10-ANALYST" as unsupported by the KB chunks, since that's an incident-specific fact given directly rather than something a MITRE/playbook doc would ever state.

**New finding from this session — free-tier quota is tight enough to hit during normal same-day testing.** Each `/explain` call costs 2 LLM requests (draft + self-critique). Re-running the script twice more the same day (once retried into a transient `503 UNAVAILABLE` "high demand" error, once into `429 RESOURCE_EXHAUSTED`) hit the free tier's `generativelanguage.googleapis.com/generate_content_free_tier_requests` cap — 20 requests/day for `gemini-3.7-flash` (the model `gemini-flash-latest` currently resolves to) on this key. In both failure cases `LLMProviderError` correctly propagated after the existing 2-attempt retry (confirming `llm_client.py`'s retry/error-wrapping behavior works as designed even under real provider failures) — but note `routes_incidents.py` doesn't catch it, so it currently surfaces as an unhandled 500 rather than a clean error response; deferred to Day 12 (`fix: llm call robustness`) per the roadmap, same as noted in the Day 9 plan. Worth remembering for Day 10's hallucination spot-check (10 more real calls) and beyond: space out same-day live-LLM runs, or budget for quota resets, when using a free-tier key for repeated manual verification.

---

## 18. Day 11 — MITRE technique mapping (Pair 1 deliverable)

Every rule's parsed `technique_id` (Day 9's tag extraction) is now checked against the real MITRE ATT&CK dataset via `app/mitre/validator.py`. Unlike a malformed rule file, an unknown/deprecated/revoked technique tag is **warn-only** — the rule still loads and still detects, since the tag being untrustworthy doesn't make the `detection`/`condition` logic wrong. See `docs/decisions.md` for the full reasoning. `app/detection/rule_loader.py`'s new `_validate_technique()` calls this right after tag parsing, logging one `logger.warning` per rule with a bad tag (distinct messages for unknown/deprecated/revoked).

### 18.1. Automated tests

```
cd backend
./venv/Scripts/python.exe -m pytest tests/mitre/test_validator.py tests/detection/test_rule_loader.py -v
```

Covers `validate_technique_id`/`validate_technique_ids` against a fake lookup table (valid/deprecated/revoked/unknown cases — 4 tests), plus `rule_loader.py`'s own technique-validation tests (a valid id loads with no warning; unknown/deprecated/revoked ids each warn but the rule still loads; every real seed rule's technique id is confirmed valid against the real dataset — these 18 tests also cover Day 7/9's rule-loading/tag-parsing basics, folded into the same file per the `backend/tests/` reorg, `docs/decisions.md`).

**Expected:** `23 passed` (4 + 18).
**Last verified:** 2026-08-19 — `23 passed in 1.08s`.

### 18.2. Manual smoke — warn-only behavior on a bad technique id

No real rule file needs editing to see this — call the validator/loader functions directly:

```
cd backend
./venv/Scripts/python.exe -c "
from app.mitre.validator import validate_technique_id
print(validate_technique_id('T1059.001'))
print(validate_technique_id('T9999.999'))
"
```

**Expected:** the first line is valid (`is_valid=True`, not deprecated/revoked); the second is `is_valid=False` (no such technique in the real ATT&CK dataset).
**Last verified:** 2026-08-19 —
```
TechniqueValidationResult(technique_id='T1059.001', is_valid=True, is_deprecated=False, is_revoked=False)
TechniqueValidationResult(technique_id='T9999.999', is_valid=False, is_deprecated=False, is_revoked=False)
```

To see the actual warning log line `rule_loader.py` emits (JSON-formatted, since Day 12's `configure_logging()` — see §19.5):
```
cd backend
./venv/Scripts/python.exe -c "
from app.core.logging import configure_logging
configure_logging()
from app.detection.rule_loader import _validate_technique
from pathlib import Path
_validate_technique(Path('example_rule.yml'), 'T9999.999')
"
```
**Expected:** one JSON warning line naming the bogus technique id.
**Last verified:** 2026-08-19 —
```json
{"timestamp": "2026-08-19T12:06:09+0530", "level": "WARNING", "logger": "app.detection.rule_loader", "message": "example_rule.yml: tagged with unknown MITRE technique id 'T9999.999'"}
```

### 18.3. Known v1 limitations

- Warn-only means a rule file with a typo'd or since-revoked technique tag stays in the running rule set indefinitely — nothing currently surfaces these warnings anywhere but the server log (no `GET /rules` health-check endpoint yet).
- All 15 real seed rules currently in `detection/rules/` have valid, non-deprecated, non-revoked technique ids (confirmed by `test_real_seed_rules_all_have_valid_technique_ids`) — the warn-only path has only been exercised against synthetic ids in tests/this smoke, not a real bad tag in the wild.

---

## 19. Day 12 — Incident endpoints + hardening + sign-off (Pair 1 deliverable)

**Milestone: Backend + Detection core complete.** Four independent pieces land together: read endpoints for the incidents Day 9's grouping has been producing all along, the rule set's final push to 15 (credential access + lateral movement), a consistent JSON shape for unhandled-exception 500s across every route, and structured JSON logging — plus an end-to-end integration test tying the whole pipeline together.

### 19.1. What changed

- **`GET /incidents`** (filters: `severity`, `status`, `start_date`, `end_date`, newest first) and **`GET /incidents/{id}`** (alerts + each alert's originating event + resolved MITRE technique name/tactics) — `app/api/routes_incidents.py`, backed by two new `app/services/incident_service.py` functions (`list_incidents`, `get_incident_alerts_with_events`).
- **5 more rules → 15 total** (`app/detection/rules/*.yml`): `lsass_memory_dump.yml` (T1003.001), `sam_registry_hive_dump.yml` (T1003.002), `rdp_lateral_movement.yml` (T1021.001), `admin_share_lateral_movement.yml` (T1021.002), `winrm_lateral_movement.yml` (T1021.006) — the first rules tagged `credential_access`/`lateral_movement`. See `docs/decisions.md` for why each fits the engine's existing categories with no engine change needed.
- **`app/core/errors.py`** — `install_exception_handlers()` registers a JSON 500 handler for any unhandled exception (Starlette's default was plain text), plus a shared `not_found()` 404 helper now used by both `GET /incidents/{id}` and the existing `explain_incident` route.
- **`app/core/logging.py`** — stdlib-only `JsonFormatter` + `configure_logging()`, wired into `app/main.py` before the app is constructed. No new dependency.
- **`tests/test_ingest_flow.py`** — the one test in the suite that runs the *real* 15-rule set (not a `FAKE_RULE`) end to end: ingest → detect → severity-score → group into an incident → `GET /incidents` → `GET /incidents/{id}` → real MITRE technique resolution from the locally cached dataset.

### 19.2. Automated tests

```
cd backend
./venv/Scripts/python.exe -m pytest tests/detection/test_rule_loader.py tests/detection/test_rules_matrix.py tests/api/test_incidents_route.py tests/test_ingest_flow.py -v
```

Covers: `detection/test_rule_loader.py`'s rule-loading + Day 11 technique-validation tests (18 — see §18.1, which also pulls in `mitre/test_validator.py`'s own 4 for a combined 23), the full 15-rule fire/no-fire matrix (31 — 1 coverage-count check + 15 fire + 15 no-fire), the existing `explain` route tests (4, now using the shared `not_found()` helper), and the new e2e test (2 — happy path + 404 case).

**Expected:** `55 passed`.
**Last verified:** 2026-08-19 — `55 passed in 2.15s`.

### 19.3. Full regression pass

```
cd backend
./venv/Scripts/python.exe -m pytest -v
```

**Expected:** `169 passed` (up from Day 10's `145` — see §16.2).
**Last verified:** 2026-08-19 — `169 passed in 14.58s`.

### 19.4. Manual smoke — rule loading (no DB needed)

```
cd backend
./venv/Scripts/python.exe -m app.detection.rule_loader
```

**Expected:** 15 lines across 4 categories (`process_creation` ×9, `registry_event` ×2, `network_connection` ×3, `file_event` ×1).
**Last verified:** 2026-08-19 — all 15 rules printed (including the 5 new ones: `Lateral Movement via Windows Admin Share`, `LSASS Memory Dump`, `RDP Lateral Movement`, `SAM/SYSTEM/SECURITY Registry Hive Dump`, `WinRM Lateral Movement`), categories as expected.

### 19.5. Manual smoke — structured JSON logging

```
cd backend
./venv/Scripts/python.exe -m uvicorn app.main:app --port 8000
```
In another shell:
```
curl http://127.0.0.1:8000/health
```

Uvicorn's own request-access line (`INFO: 127.0.0.1:... "GET /health HTTP/1.1" 200 OK`) is *not* JSON — that's uvicorn's own `uvicorn.access` logger, which has its own handler and doesn't route through `configure_logging()`'s root handler (expected, not a bug — `configure_logging()` targets this project's own `app.*` loggers). To see a real JSON line from an `app.*` logger, trigger one that actually calls `logger.warning`/`.info`/`.exception` — §19.6 below does exactly that via the new error handler.
**Last verified:** 2026-08-19 — confirmed `/health` still returns `{"status":"ok"}` under the new logging setup with no regression; the JSON-formatted line is captured in §19.6.

### 19.6. Manual smoke — consistent error handling (no Docker needed)

The clearest way to see the Day 12 fix is to hit a DB-touching route **without Postgres running** — before Day 12 this surfaced as a raw, unhandled traceback; now `core/errors.py`'s handler catches it and returns clean JSON.

With the server from §19.5 still running (Docker/Postgres left off on purpose for this check):
```
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://127.0.0.1:8000/incidents
curl -s http://127.0.0.1:8000/incidents
```

**Expected:** `HTTP 500`, body `{"detail":"internal server error"}` — not a raw psycopg2/SQLAlchemy traceback.
**Last verified:** 2026-08-19 — exactly as expected, for both `GET /incidents` and `POST /ingest` (same underlying DB-connection failure). The server log shows the JSON-formatted error line this produced (traceback truncated here):
```json
{"timestamp": "2026-08-19T12:07:12+0530", "level": "ERROR", "logger": "app.core.errors", "message": "unhandled error on GET /incidents", "exc_info": "Traceback (most recent call last):\n ... sqlalchemy.exc.OperationalError: (psycopg2.OperationalError) connection to server at \"localhost\" ... port 5433 failed: Connection refused ..."}
```
This confirms both halves of the Day 12 fix at once: the *response* the client sees is clean/consistent JSON, and the *server-side log* of the same failure is structured JSON (§19.5), not an unformatted stack trace dumped to stderr.

Stop the server afterward the same way as §4 (Ctrl+C, or `netstat -ano | findstr :8000` + `taskkill /F /PID <pid>` on Windows).

### 19.7. Live server + Postgres verification — full incident flow

```
cd <repo root>
docker compose up -d db
docker compose exec db pg_isready -U nightowl
cd backend
./venv/Scripts/python.exe -m uvicorn app.main:app --port 8000
```
In another shell:
```
curl -F "file=@../data/sample_logs/sysmon_demo.evtx;type=application/octet-stream" http://127.0.0.1:8000/ingest
curl http://127.0.0.1:8000/incidents
curl http://127.0.0.1:8000/incidents?severity=high
curl http://127.0.0.1:8000/incidents/<id-from-the-list-response>
curl http://127.0.0.1:8000/incidents/999999
```

**Expected:** the ingest happy path now also returns `incident_ids`; `GET /incidents` returns `{"incidents":[...],"count":N}`; the severity filter narrows the list; the detail call returns the incident with its `alerts` (each nesting its `event`) and resolved `techniques`; the unknown id returns `HTTP 404 {"detail":"incident 999999 not found"}`.

**Last verified:** 2026-08-19, later same day — Docker Desktop was started (`docker ps` had failed earlier in this session, same "dockerDesktopLinuxEngine" gap noted below), `docker compose up -d db` + `pg_isready` succeeded, `alembic upgrade head` applied cleanly (`alembic current` → `6b1a55c7f800 (head)`), and `\dt` confirmed all 6 tables. `sysmon_demo.evtx` still doesn't contain a matching event for any of the 15 rules (same non-defect as §9.3/§12.4/§13.4 — `rule_matches: 0`), but the named Docker volume had persisted one real incident from an earlier session's live demo (§14.4's `DEMO-HOST-D9` incident), which was enough to exercise every read path for real:

```json
GET /incidents
{"incidents":[{"id":1,"title":"Suspicious Encoded PowerShell Command on DEMO-HOST-D9","status":"open","severity":"critical","host":"DEMO-HOST-D9","mitre_technique_ids":["T1059.001","T1053.005"],"created_at":"2026-08-17T05:13:16.311996Z"}],"count":1}

GET /incidents?severity=critical   -> same 1 incident, count:1
GET /incidents?severity=low        -> {"incidents":[],"count":0}   (filter correctly excludes it)

GET /incidents/1
{"id":1,"title":"Suspicious Encoded PowerShell Command on DEMO-HOST-D9","status":"open","severity":"critical","host":"DEMO-HOST-D9","created_at":"2026-08-17T05:13:16.311996Z","mitre_technique_ids":["T1059.001","T1053.005"],"techniques":[{"id":"T1059.001","name":"PowerShell","tactics":["execution"]},{"id":"T1053.005","name":"Scheduled Task","tactics":["execution","persistence","privilege-escalation"]}],"alerts":[{"id":2,"rule_id":"5b1f3a2e-6c1e-4f6a-9b8e-2f8b1a9d6e11","matched_at":"2026-08-17T05:13:16.311996Z","severity":"critical","event":{"id":19,"host":"DEMO-HOST-D9","timestamp":"2026-08-19T12:00:00Z","event_id":1,"process":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","command_line":"powershell.exe -EncodedCommand aQBlAHgA","user":null}},{"id":3,"rule_id":"3c7b9e42-6d1a-4f8c-b2e5-9a4d7c1f6b38","matched_at":"2026-08-17T05:13:16.311996Z","severity":"high","event":{"id":20,"host":"DEMO-HOST-D9","timestamp":"2026-08-19T12:00:00Z","event_id":1,"process":"C:\\Windows\\System32\\schtasks.exe","command_line":"schtasks.exe /create /tn Updater /tr payload.exe /sc onlogon","user":null}}]}

GET /incidents/999999
HTTP 404  {"detail":"incident 999999 not found"}
```

Confirms, for real: filters correctly include/exclude by severity; the detail response nests both alerts with their originating events (correct `process`/`command_line`/`host` per event, correct `rule_id` per alert); both MITRE technique ids resolved to real names/tactics from the locally cached dataset (`T1053.005`'s 3-tactic list included), not just the raw ids already visible in `mitre_technique_ids`; and the 404 path works identically to the no-Postgres case (§19.6) except with the correct status code now that the DB is actually reachable. Server stopped afterward (found the listening PID via `Get-NetTCPConnection -LocalPort 8000`, `Stop-Process -Force`) — Postgres container left running (data persists in the named volume for the next session, same as every prior Docker-gated check in this guide).

### 19.8. Known v1 limitations

- `GET /incidents` filters are exact-match/range only — no free-text search. **Pagination added Day 13** (§22) — see there instead of here.
- The unhandled-exception JSON handler returns a single generic `"internal server error"` message for every unhandled exception type — deliberately generic so internal details (stack traces, DB connection strings) never leak to a client; full detail is only in the structured server-side log (§19.6).
- `core/logging.py`'s JSON formatter covers this project's own loggers; uvicorn's built-in access/error loggers keep their own default (non-JSON) format, since overriding those isn't part of what "structured JSON logging" was asking for here (see §19.5).

---

## 20. Day 11 — Incident chat endpoint (Pair 2 deliverable)

`chat_messages` gets a real service (`app/services/chat_service.py`, persistence only) and a RAG-orchestration counterpart (`app/rag/chat_service.py`, mirrors `rag/explain_service.py`'s retrieve→prompt→LLM composition but for a free-form follow-up question, no self-critique pass), wired up behind `POST /incidents/{id}/chat` (`app/api/routes_chat.py`). Each call persists the user's message, retrieves KB context scoped to the incident (same `technique_id`-filtered retrieval as `/explain`) plus prior turns, generates a grounded reply, persists it, and returns it with source attribution. `GET /incidents/{id}/chat` (history) and prompt-robustness hardening are Day 12 scope — not built here.

### 20.1. Automated tests

```
cd backend
./venv/Scripts/python.exe -m pytest tests/rag/test_chat_service.py tests/rag/test_prompts.py tests/api/test_chat_route.py -v
```

Covers: `rag/chat_service.py`'s retrieve→answer pipeline (4 — reply/chunks returned, the new message folds into the retrieval query, history+message reach the prompt, an `LLMProviderError` from `generate()` propagates uncaught), the new chat-prompt template additions to `rag/prompts.py` (5 — `format_chat_history` empty/populated, `build_chat_prompt` message shape/content/no-history-or-chunks fallback, alongside the existing 10 explain-prompt cases), and `routes_chat.py`'s `POST /incidents/{id}/chat` (3 — happy path persists both the user and assistant `ChatMessage` rows and returns the assistant turn + sources, a second call's `history` includes the first turn, 404 when the incident doesn't exist). Fully offline — `generate_chat_reply` is mocked in the route tests, and `retrieve`/`generate` are mocked in the rag-service tests; no network call, no real API key used.

**Expected:** `24 passed` (4 + 15 in `test_prompts.py`, which grew from 10 to 15 + 3).
**Last verified:** 2026-08-19 — `24 passed in 0.20s`.

### 20.2. Full regression pass

```
cd backend
./venv/Scripts/python.exe -m pytest -v
```

**Expected:** `181 passed` (up from Day 12's `169` — see §19.3 — +12 new: 4 rag-service + 5 prompt-template + 3 route).
**Last verified:** 2026-08-19 — `181 passed in 10.77s`.
**Re-verified 2026-08-19 (independent full-repo recheck, fresh `git fetch` confirmed `main` in sync with `origin/main`, no unpulled commits):** `181 passed in 18.33s`, zero failures — guide content confirmed current against HEAD (`2cdccd6`). Required one venv fix first: `langchain-groq` (added to `requirements.txt` by the Day 10 Groq commit, `9cf6913`) wasn't yet installed in `backend/venv` — see Troubleshooting.

### 20.3. Manual check — in-memory SQLite substitution (no Docker needed)

Docker isn't installed in this environment (see Troubleshooting), so this exercises the real route code (`routes_chat.py`'s incident lookup, `_incident_to_dict`, history snapshot, response building) against a real `Incident` row via the same `dependency_overrides[get_db]` substitution the automated route tests use. A live-LLM smoke test (deliberately calling the real Gemini/Groq API) was intentionally **not** planned this round to conserve the free-tier daily quota (§17.3 already flagged how tight 20 requests/day is) — the fully-mocked automated suite above is the primary test evidence for this feature.

```python
# from backend/, PYTHONPATH=. ./venv/Scripts/python.exe, ad hoc:
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models.incident import Incident

engine = create_engine("sqlite+pysqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
Base.metadata.create_all(engine)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

def _override_get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = _override_get_db
client = TestClient(app)

with SessionLocal() as db:
    incident = Incident(title="Suspicious PowerShell execution on WIN10-ANALYST", status="open",
                         severity="high", mitre_technique_ids=["T1059.001"],
                         created_at=datetime.now(timezone.utc), host="WIN10-ANALYST")
    db.add(incident); db.commit(); db.refresh(incident)
    incident_id = incident.id

print(client.post(f"/incidents/{incident_id}/chat", json={"message": "hi"}).status_code)
print(client.post("/incidents/999999/chat", json={"message": "hi"}).json())
```

**Expected:** the 404 case returns `{"detail": "incident 999999 not found"}`; the real-incident case reaches `generate_chat_reply` (not mocked here) and depends on whether a working `LLM_API_KEY`/`GROQ_API_KEY` with remaining free-tier quota is configured.

**Last verified:** 2026-08-19 — the 404 case ran clean: `404 {'detail': 'incident 999999 not found'}`. The real-incident case surfaced an unplanned finding: `backend`'s root `.env` (gitignored, resolved from the module's own file location per the Day 3 `config.py` fix noted in §16.4) already has a real `LLM_API_KEY` configured from earlier sessions, so this "no LLM call" check unintentionally made one — and hit the free-tier quota (`429 RESOURCE_EXHAUSTED ... GenerateRequestsPerDayPerProjectPerModel-FreeTier, limit: 20, model: gemini-3.7-flash`), already exhausted from Day 9/10's live-LLM testing (§17.3/hallucination spot-check). `llm_client.generate()`'s retry-then-`LLMProviderError` behavior worked exactly as designed (confirmed the same way §17.3 confirmed it under real quota exhaustion) — but `TestClient`'s default `raise_server_exceptions=True` re-raises the exception into the calling script rather than showing what a real HTTP client would see (a clean `500 {"detail":"internal server error"}` from `core/errors.py`'s handler, per §19.6's same finding for `/incidents`). No further live-LLM calls were made after this to avoid burning more of the shared daily quota — **flagging for the user:** the configured Gemini key's free-tier quota is currently exhausted; a live end-to-end chat verification (real retrieval + real LLM reply) needs either a quota reset or a different key, and should be run deliberately (budgeted, one call) rather than incidentally.

---

## 21. Postman Collection — All Endpoints (Day 3–12 + Pair 2 Day 11 Chat)

A real, importable Postman collection now lives at `docs/postman/NightOwl.postman_collection.json`, with a matching environment at `docs/postman/NightOwl.postman_environment.json`. It covers every endpoint that exists through Day 12, plus Pair 2's Day 11 chat endpoint — this is the answer to "test it in Postman" without retyping each request by hand.

**Day 13 additions (see §22.7 for the full walkthrough):** every request below except Health Check now sends an `X-API-Key` header wired to a new `api_key` collection/environment variable (default empty, matching `API_KEY` being unset by default — harmless either way, since `require_api_key` only checks the header when the server has a key configured). The Incidents folder also gained two new pagination requests. And because the Day 13 rate limiter applies globally (including to every request in this collection), clicking through the full run order below in quick succession could occasionally trip a `429` — if that happens, just wait a few seconds for the token bucket to refill and retry.

### 21.1. Import

1. Postman → **Import** → select both `docs/postman/NightOwl.postman_collection.json` and `docs/postman/NightOwl.postman_environment.json` (drag-and-drop both, or import one at a time).
2. Top-right environment dropdown → select **NightOwl Local**.
3. If your server runs on a different host/port, edit the environment's `base_url` variable (default `http://127.0.0.1:8000`).

### 21.2. Suggested run order

The collection is grouped into 6 folders (**Health**, **Ingest**, **MITRE**, **Incidents**, **Explain**, **Chat**); each request's Postman description states its own DB/API-key requirement, but the practical run order is:

1. **Health → Health Check** — no setup beyond `uvicorn` running. Expect `200 {"status":"ok"}`.
2. **Ingest → Ingest - Happy Path (sysmon_demo.evtx)** — needs live Postgres (§3/§19.7). Click the request's `file` field's **Select File** button and choose `data/sample_logs/sysmon_demo.evtx` from the repo. Expect `200` with `records_read`/`events_ingested`/`rule_matches`/`alerts_created`/`incident_ids`. **Without Postgres**, expect the new clean `500 {"detail":"internal server error"}` instead (§19.6) — this is itself a valid, useful check.
3. **Ingest → the 3 error-case requests** — no DB needed (they fail validation/parsing before any DB call). Each request's description says exactly what file to pick (a non-`.evtx` file / a 0-byte file / a `.evtx`-named file with garbage bytes). Expect `400` with the specific `detail` message noted in each request's description (matches §9.3).
4. **MITRE → List MITRE Techniques** — no DB needed. Expect `200 {"techniques":[...],"count":858}`.
5. **Incidents → List Incidents - All** — needs live Postgres. Expect `200 {"incidents":[...],"count":N}`.
6. **Incidents → List Incidents - Paginated (limit=1, offset=0)** (Day 13) — needs live Postgres with more than one incident. Expect `200` with exactly 1 item in `incidents`, `count:1`, and `total` equal to the full match count (same `total` you'd get from step 5). Bump `offset` to page through the rest.
7. **Incidents → List Incidents - Limit Above Cap (expect 422)** (Day 13) — no DB needed, pydantic rejects it first. Expect `422`.
8. **Incidents → the 3 filtered variants** (severity/status/date range) — edit the query param values to match real data from step 5 if you want a non-empty result; the defaults are placeholders.
9. **Incidents → Get Incident Detail** — first update the `incident_id` environment variable to a real id from step 2's or step 5's response, then send. Expect `200` with `alerts[]` (each nesting its `event`) and resolved `techniques[]`.
10. **Incidents → Get Incident Detail - 404** — needs live Postgres (to determine the id truly doesn't exist). Expect `404 {"detail":"incident 999999 not found"}`.
11. **Explain → Explain Incident** — needs live Postgres, a real `incident_id`, and a real `LLM_API_KEY` in `backend`'s `.env` (2 live Gemini calls per request — mind the free-tier daily quota, §17.3/Troubleshooting). Expect `200` with `explanation`/`recommended_response`/`sources[]`.
12. **Chat → Chat With Incident** — needs live Postgres, a real `incident_id`, and a real `LLM_API_KEY`/`GROQ_API_KEY` (1 live LLM call per request). Each call persists both the user message and the assistant reply, so a second call against the same `incident_id` has real conversation history to draw on. Expect `200` with `incident_id`/`role` (`"assistant"`)/`content`/`sources[]`.
13. **Chat → Chat With Incident - 404** — needs live Postgres. Expect `404 {"detail":"incident 999999 not found"}`.
14. If you've set `API_KEY` in `backend`'s `.env`, also work through §22.7 for the auth/rate-limit-specific checks (401 on a missing/wrong key, 429 on a fast burst).

### 21.3. Why Postman for `/ingest` specifically

This environment's git-bash `curl` only path-translates a POSIX path when it *leads* the argument — embedded after `-F file=@`, a path starting with `/` fails to resolve (see the Troubleshooting table). Postman's native file picker has no such quirk: click **Select File**, browse to the repo, done. This is the main practical reason to prefer Postman over `curl` for the multipart upload steps, on top of it just being a friendlier way to work through the full endpoint list interactively.

**Last verified:** 2026-08-19 — collection/environment JSON validated as well-formed (Postman v2.1 collection schema, standard environment export shape); the underlying HTTP behavior each request documents was verified via the equivalent `curl`/automated-test calls in §16/§19/§20 (same server, same routes) rather than a live Postman GUI session in this environment. If you run the actual import-and-click-through afterward, that's the final end-to-end confirmation.

---

## 22. Day 13 — Production Hardening (Pair 1 deliverable)

Four independent pieces, scoped to Pair 1's half of the roadmap's Day 13 "Production Hardening" phase (Pair 2's LLM caching/audit log/CI pipeline are the teammates' own work, not covered here): shared-secret header auth on every route, `limit`/`offset` pagination on `GET /incidents`, an in-memory rate limiter, and containerizing the backend.

### 22.1. What changed

- **`app/core/auth.py`** — new `require_api_key` FastAPI dependency, checked against `settings.api_key`. Applied via `dependencies=[Depends(require_api_key)]` on every `app.include_router(...)` call in `app/main.py` (ingest, mitre, incidents, chat) — `/health` is defined directly on `app` so it's unauthenticated by design (health checks/load balancers shouldn't need a key). **Empty `API_KEY` (the default) disables enforcement entirely** — same "empty string = not configured" convention `llm_api_key`/`groq_api_key` already use — so existing workflows (Postman, the test suite) keep working with no header until an operator opts in.
- **`app/core/rate_limit.py`** — hand-rolled in-memory token-bucket limiter (no new dependency — `slowapi` isn't installed and the project is stdlib-first), registered as ASGI middleware in `app/main.py` and applied to every route including `/health`. Keyed by client host; `RATE_LIMIT_PER_MINUTE <= 0` disables it. `backend/tests/conftest.py` gained an `autouse=True` fixture resetting the limiter's global bucket state before/after every test — necessary because `app.main.app` is a module-level singleton and Starlette's `TestClient` reports every request's client as the same fixed `("testclient", 50000)` tuple, so without the reset, token consumption from one test would leak into later, unrelated tests as spurious `429`s.
- **Pagination** — `app/services/incident_service.py`'s `list_incidents` gained `limit`/`offset` params, plus a new `count_incidents` (both share a `_filtered_incidents_stmt` helper so the two can't drift out of sync on filter logic). `GET /incidents` (`app/api/routes_incidents.py`) gained `limit` (default 50, max 200 → `422` above that) and `offset` (default 0, `>= 0`) query params, and `IncidentListResponse` gained `total` (grand total matching the filters, independent of the page), `limit`, `offset` fields alongside the existing `count` (which still means "items in this page," unchanged, so the Day 12 e2e test in `tests/test_ingest_flow.py` needed no changes).
- **`backend/Dockerfile`** (new) + root **`.dockerignore`** (new) + **`docker-compose.yml`** — multi-stage (builder + runtime), non-root (`appuser`, uid 1000) image. Build context is the **repo root**, not `backend/`, and the image mirrors the same `backend/app/...` nesting rather than flattening it — `app/core/config.py`, `app/mitre/loader.py`, and `app/rag/chroma_client.py` all resolve paths via `Path(__file__).resolve().parents[3]` (repo root, 3 levels above `app/`), so this was necessary to avoid silently breaking `/mitre/techniques`, incident-detail technique resolution, and Chroma-backed retrieval inside the container with zero app-code changes. `docker-compose.yml`'s `db` service gained a `pg_isready` healthcheck; the new `backend` service depends on it (`condition: service_healthy`) and overrides `.env`'s `DATABASE_URL` (`localhost:5433`, host-machine-only) with the compose-network-relative `db:5432`.

### 22.2. Automated tests

```
cd backend
./venv/Scripts/python.exe -m pytest tests/core tests/services/test_incident_service.py tests/api/test_incidents_list_route.py -v
```

Covers: `tests/core/test_auth.py` (10 — disabled-by-default, missing/wrong/correct header, `/health` bypass, every feature router individually including `/ingest`'s multipart case), `tests/core/test_rate_limit.py` (5 — within-capacity, over-capacity `429`, refill-over-time, `<= 0` disables it, buckets start empty each test), plus the new pagination coverage in `test_incident_service.py` (4 new, alongside 7 pre-existing incident-grouping tests in the same file — limit/offset paging, unpaginated default, count matches total regardless of limit, count respects the same filters as list) and `test_incidents_list_route.py` (5 — default limit is 50, `total` beyond one page, distinct pages, `limit`/`offset` validation `422`s).

**Expected:** `31 passed` — 24 new Day 13 tests (10 + 5 + 4 + 5) plus 7 pre-existing `test_incident_service.py` tests that this command's file-level scope also picks up.
**Last verified:** 2026-08-20 — `31 passed in 2.59s`. (Note: an earlier draft of this section claimed `24 passed`, undercounting because it forgot the command runs the *whole* `test_incident_service.py` file, not just its 4 new pagination tests — corrected here after actually running it.)

### 22.3. Full regression pass

```
cd backend
./venv/Scripts/python.exe -m pytest -v
```

**Expected:** `205 passed` (up from Day 12's `181` — 24 new Day 13 tests, no existing test needed to change).
**Last verified:** 2026-08-20 — `205 passed in 22.28s`.

### 22.4. Manual smoke — API key auth

```
cd backend
./venv/Scripts/python.exe -m uvicorn app.main:app --port 8000
```
With `API_KEY` left unset in `.env` (the default):
```
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://127.0.0.1:8000/incidents
```
**Expected:** `HTTP 200` — auth disabled by default.

Then set `API_KEY=some-test-value` in `.env`, restart uvicorn, and repeat:
```
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://127.0.0.1:8000/incidents
curl -s -o /dev/null -w "HTTP %{http_code}\n" -H "X-API-Key: wrong" http://127.0.0.1:8000/incidents
curl -s -o /dev/null -w "HTTP %{http_code}\n" -H "X-API-Key: some-test-value" http://127.0.0.1:8000/incidents
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://127.0.0.1:8000/health
```
**Expected:** `401`, `401`, `200`, `200` (health always bypasses).

**Last verified:** 2026-08-20 — ran for real against the live Docker stack (`docker compose up -d`, see §22.6 for what it took to get there) once it came up: `GET /incidents` with `API_KEY` unset → `200`; with `API_KEY=nightowl-test-key` set (container recreated to pick it up) → no header `401`, `X-API-Key: wrong` `401`, `X-API-Key: nightowl-test-key` `200`, `GET /health` with no header `200`. Exactly the expected sequence. `.env` was reverted and the container recreated again afterward, back to the default auth-disabled state. (Also covered by `tests/core/test_auth.py` — `10 passed` — see §22.2.)

### 22.5. Manual smoke — pagination

Needs live Postgres with more than one incident (§19.7 shows how to get one via the sample log, or insert test rows directly).
```
curl "http://127.0.0.1:8000/incidents?limit=1&offset=0"
curl "http://127.0.0.1:8000/incidents?limit=500"
curl "http://127.0.0.1:8000/incidents?offset=-1"
```
**Expected:** first call returns `{"incidents":[...1 item...],"count":1,"total":N,"limit":1,"offset":0}`; second and third calls both return `HTTP 422` (limit capped at 200, offset can't be negative).

**Last verified:** 2026-08-20 — ran for real against the live Docker stack: `curl "http://127.0.0.1:8000/incidents?limit=1&offset=0"` returned `{"incidents":[{"id":1,"title":"Suspicious Encoded PowerShell Command on DEMO-HOST-D9",...}],"count":1,"total":1,"limit":1,"offset":0}` (only 1 incident existed in this dev DB); `limit=500` → `422`; `offset=-1` → `422`. Matches expectations exactly. (Also covered by `tests/api/test_incidents_list_route.py` — `5 passed` — see §22.2, which additionally confirms the disjoint-pages case with more than one page of data.)

### 22.6. Manual smoke — rate limiting + Docker build status

With `RATE_LIMIT_PER_MINUTE` left at its default (60), firing 65+ requests at any route in quick succession (well under a second, so refill during the burst is negligible) trips it:
```
for i in $(seq 1 65); do curl -s -o /dev/null -w "%{http_code} " http://127.0.0.1:8000/health; done; echo
```
**Expected:** a run of `200`s, then `429` for the remainder once the bucket empties — body `{"detail":"rate limit exceeded"}` on the `429`s. (Contrary to an earlier draft of this section, this *is* practical to hand-verify — no need to wait a minute, just fire the burst fast.)

**Last verified:** 2026-08-20 — fired for real against the live Docker stack: a 70-request burst at `/health` returned 68× `200` then `429 429` (capacity 60, some tokens already consumed by earlier auth-test requests in the same minute); a second, tighter burst showed the same pattern repeatedly (`200`s until the bucket empties, then a run of `429`s, recovering to `200`s again as tokens refilled between bursts). The exact `429` body (`{"detail":"rate limit exceeded"}`) is confirmed by `tests/core/test_rate_limit.py::test_over_capacity_returns_429` (part of the `5 passed` in §22.2) rather than re-captured from a live response, since the token bucket kept refilling between the live burst and grabbing the body — the transition to `429` itself was captured live and is real.

**Docker build:** `docker compose build backend` was run against this repo (this session, after fixing an unrelated full-disk condition that had broken the daemon). It hit the same corporate-network TLS interception already documented in §0 ("Windows + corporate/AV network only" `pip-system-certs` note) — except that fix is host-side (points Python at Windows' trust store) and doesn't help inside the container's bare Debian image, which has no such store. Fixed by scoping `--trusted-host pypi.org --trusted-host files.pythonhosted.org` to the builder stage's `pip install` only (build-time, doesn't weaken the runtime image's own TLS behavior).

**Full `docker compose up` end-to-end: done and verified this session.** Getting there took three real, distinct problems, worth recording since they'll recur if this environment's disk fills up again:
1. **Stale WSL2 disk-mount lock.** Force-killing Docker Desktop mid-build (to recover from the full-disk condition) left `docker_data.vhdx` attached from the killed process. Every subsequent `docker info`/`docker ps`/build call just hung, because the WSL `docker-desktop` distro's `wsl-bootstrap` failed with `WSL_E_USER_VHD_ALREADY_ATTACHED` → `mke2fs: /dev/sdd is apparently in use by the system` → the engine flipped straight to `stopping` without ever finishing startup. **Fix:** `wsl --shutdown` (clears all disk attachments) before relaunching Docker Desktop.
2. **Corrupted image layers.** The first `docker compose build backend` reported success, but the container crash-looped on `ImportError: cannot import name 'main' from 'uvicorn.main'`. Inspecting the image showed every Python file in the installed `uvicorn` package was **0 bytes** — the layer-export step had run for ~5 minutes right as the host disk hit 0 bytes free, and the writes got silently truncated even though `pip install` itself had already reported success earlier in the same build. A same-session rebuild reproduced the exact same corruption, because the disk was still critically low (5.2GB free) at rebuild time. **Fix:** `docker rmi` the corrupted image, `docker builder prune -af` (reclaimed 14.5–24GB), confirm real free space (`df -h`), *then* rebuild — a starved rebuild just recreates the same corruption.
3. **WSL2's vhdx doesn't auto-shrink.** Freeing space *inside* Docker's storage doesn't shrink `docker_data.vhdx` on the Windows side — it grew from ~21GB to ~32GB over these rebuilds and stays that size. `Optimize-VHD`/`diskpart compact vdisk` would reclaim the real Windows-side space, but both need admin elevation this session didn't have — worth doing from an elevated prompt if disk pressure recurs.

**Verified for real** (`curl` from the host against the running containers, both `db` and `backend` up via `docker compose up -d`):
```
$ curl -s -o /dev/null -w "HTTP %{http_code}\n" http://127.0.0.1:8000/health
HTTP 200
$ curl -s http://127.0.0.1:8000/health
{"status":"ok"}
$ curl -s http://127.0.0.1:8000/mitre/techniques | python -c "import sys,json; print(json.load(sys.stdin)['count'])"
858
```
`/health` responds `200`, and `/mitre/techniques` returns the same `count: 858` as the non-Docker run — confirming the `./data` volume mount (`Path(__file__).resolve().parents[3]`-relative path resolution, §22.1) works correctly inside the container. **Last verified:** 2026-08-20.

### 22.7. Postman — Day 13 additions

`docs/postman/NightOwl.postman_collection.json` and `NightOwl.postman_environment.json` were updated this session to cover auth and pagination (see §21 for the base collection). Re-import both if you already had the old versions loaded — Postman will update the existing collection/environment in place as long as you keep the same names.

**Auth (401 → 200):**
1. Leave `API_KEY` unset in `.env` and the `api_key` environment variable blank (its default) — every request should behave exactly as it did pre-Day 13, e.g. **Health → Health Check** and **Incidents → List Incidents - All** both `200`.
2. Set `API_KEY=some-test-value` in `.env` and restart uvicorn. In Postman, set the **NightOwl Local** environment's `api_key` variable to something else, e.g. `wrong` — send **Incidents → List Incidents - All** → expect `401 {"detail":"invalid or missing API key"}`.
3. Change `api_key` to blank again (missing header) and send the same request → still `401`.
4. Change `api_key` to `some-test-value` (matching `.env`) → same request now → `200`.
5. **Health → Health Check** → `200` regardless of `api_key` — it's exempt by design.
6. Set `.env`'s `API_KEY` back to unset when you're done, restart uvicorn, and set the Postman `api_key` variable back to blank, so the collection matches the default (auth-disabled) dev state again.

**Pagination:**
- **Incidents → List Incidents - Paginated (limit=1, offset=0)** — expect `200` with exactly one item and a `total` matching however many incidents actually exist. Edit the `offset` query param (1, 2, ...) to page through the rest; `total` stays constant.
- **Incidents → List Incidents - Limit Above Cap (expect 422)** — expect `422`, no DB round-trip needed. Swap `limit=500` for `offset=-1` in the request URL to see the negative-offset case, same `422` outcome.

**Rate limiting (429) via Postman's Collection Runner:**
1. Postman → open the **NightOwl -- Day 3-13 API** collection → **Run** (Collection Runner).
2. Select just the **Health → Health Check** request, set **Iterations** to `70`, **Delay** to `0ms`, and run.
3. **Expected:** the first ~60 iterations return `200`, then the rest return `429` with `{"detail":"rate limit exceeded"}` — the run summary's status-code breakdown shows the split directly. Wait roughly a minute (the bucket refills at 1 token/sec at the default 60/min capacity) before re-running other requests if you want a clean slate.

### 22.8. Explain endpoint hang/500 fix + severity-filter data finding (found via manual Postman testing)

Three requests were screenshotted during a manual Postman pass over the Day 13 work: `GET /incidents?limit=500`, `GET /incidents?severity=high`, and `POST /incidents/{id}/explain`. Root-caused and fixed/verified as follows.

**`limit=500` → `422`** — by design, no change. `routes_incidents.py`'s `limit: int = Query(default=50, ge=1, le=200)` rejects it, exactly as `test_limit_above_cap_returns_422` (§22.5) already asserts.

**`severity=high` → `200` with zero results** — a data finding, not a filter bug. `incident_service.py`'s severity filter is a plain, correct `Incident.severity == severity` exact match. Of the 15 seed detection rules, only 4 (`powershell_execution_policy_bypass`, `registry_run_key_persistence`, `scheduled_task_creation_schtasks`, `scheduled_task_creation_powershell`) resolve to final severity `"high"` after `severity_service.compute_severity()`'s tactic-weight scoring — the rest resolve to `"critical"`. Confirmed live: `GET /incidents?limit=5` on this machine's DB returns exactly one incident, from `suspicious_encoded_powershell`, with `"severity": "critical"` — so `severity=high` correctly returns zero rows because nothing ingested so far has tripped one of those 4 specific rules. Diagnostic query: `SELECT DISTINCT severity, count(*) FROM incidents GROUP BY severity;` (via `docker compose exec db psql -U nightowl -d nightowl`).

**`POST /incidents/{id}/explain` hung ~107s then returned a masked `500 {"detail":"internal server error"}`** — a real bug, now fixed. Two issues stacked in `backend/app/rag/llm_client.py`'s `get_llm_client()`:
1. `ChatGoogleGenerativeAI`/`ChatGroq` were constructed with no `timeout=`, which traces down through `langchain_google_genai` → `google.genai._api_client` → `httpx` as `Timeout(None)` — no timeout at any layer. Fixed by adding `timeout=settings.llm_timeout_seconds` (new setting, `config.py`, default 30s, override via `LLM_TIMEOUT_SECONDS` in `.env`).
2. Separately, `ChatGoogleGenerativeAI` defaults to its own internal `max_retries=6` (`ChatGroq` defaults to `2`) — an SDK-level retry-with-backoff that honors the server's suggested retry delay (observed ~14-29s per round on a `429 RESOURCE_EXHAUSTED`), stacking underneath `llm_client.generate()`'s own outer retry-once logic. Fixed by passing `max_retries=1` to `ChatGoogleGenerativeAI` (per its own docstring: `0` is read as "use the SDK default," `1` means exactly one attempt, no internal retry) and `max_retries=0` to `ChatGroq`.
3. Additionally, `core/errors.py`'s catch-all `Exception` handler was flattening a well-formed `LLMProviderError` (missing key / quota exhausted / timed out) into the same opaque `internal server error` as an actual unhandled bug. Fixed by adding a dedicated `@app.exception_handler(LLMProviderError)` returning `503` with the real message, registered ahead of the generic handler (FastAPI dispatches by most-specific type, so no reordering was needed).

**Verified live** against this machine's real (quota-exhausted) Gemini key, incident id 1:
```
$ time curl -s -w "\nHTTP_STATUS:%{http_code} TIME:%{time_total}s\n" -X POST http://localhost:8000/incidents/1/explain
{"detail":"LLM call failed after 2 attempts: Error calling model 'gemini-flash-latest' (RESOURCE_EXHAUSTED): 429 ... Quota exceeded ... limit: 20 ... Please retry in 29.4s"}
HTTP_STATUS:503 TIME:27.65s
```
Before the `max_retries` fix, the same request (timeout fix only) took **100.15s** to return the same 503 — confirming the SDK-internal retry loop was the dominant cost, not just the missing timeout. Before *any* fix, this same failure mode returned a masked `500 {"detail":"internal server error"}` after ~107s of hanging.

Also verified the **happy path** end-to-end (retrieval + draft + self-critique) via the configured Groq fallback key (temporary `LLM_PROVIDER=groq` env override for this one check only — `.env`'s committed `LLM_PROVIDER=gemini` default was not changed): `generate_explanation()` against the same incident completed in **14.5s**, returned 5 retrieved chunks, and produced a correct three-section explanation (What happened / Why it matters / Recommended next steps) plus a working self-critique confidence check. This confirms the pipeline itself is correct — the original bug was purely the missing timeout/retry-tuning/error-masking around the LLM call, not the RAG or prompt logic.

**Root cause of the original quota exhaustion:** repeated live-Gemini smoke tests across sessions (§10.4, §11.3, §17.3) each cost 2 of the free tier's 20 requests/day — by the time of this pass the day's quota was already spent, which is why this bug surfaced as a *guaranteed* 429 rather than an occasional one. Not a code issue; see the Troubleshooting table's `429 RESOURCE_EXHAUSTED` row for the mitigation.

**Last verified:** 2026-08-21.

### 22.9. Known v1 limitations

- Rate limiting is a single uniform limit across every route (including `/health`) keyed by client IP — no per-route tiering (e.g. a stricter limit specifically on the LLM-backed `/explain`/`/chat` routes), and no `X-Forwarded-For` handling if a reverse proxy is ever added in front.
- Auth is a single shared secret, not per-user/per-team credentials — fine for a small team demo, not a real multi-tenant auth story.
- `backend/scripts/` (e.g. `build_kb.py`) isn't copied into the Docker image — the knowledge-base build stays a host-venv workflow; the API itself never calls it at runtime.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `failed to connect to the docker API ... dockerDesktopLinuxEngine` | Docker Desktop isn't running | Launch Docker Desktop and wait ~10–20s, then retry |
| `SSLError: CERTIFICATE_VERIFY_FAILED` on any GitHub/HuggingFace call | Corporate/AV TLS interception not trusted by Python's `certifi` bundle | `pip install pip-system-certs` in the venv (see Prerequisites) |
| `pg_isready` never succeeds / port 5433 already in use | Another Postgres instance already bound to 5433, or the container needs more time | `docker compose ps`, `docker compose logs db`; confirm nothing else owns host port 5433 |
| First run of `test_setup_integrations.py` or `build_kb.py` is slow (~1–2 min) | `sentence-transformers`/`torch` downloading model weights and MITRE JSON on first use | Expected once; subsequent runs use local caches (`data/mitre/enterprise-attack.json`, HF cache, `data/chroma/`) |
| `uvicorn` port 8000 still bound after stopping | Reload/watcher spawned a child process with a different PID | `netstat -ano \| findstr :8000` then `taskkill /F /PID <pid>` |
| `pytest -v` (bare, whole `tests/` dir) collection-errors with `ModuleNotFoundError: fastapi`/`sqlalchemy`/`Evtx` | Those Pair 1 deps aren't installed in this venv | `SETUPTOOLS_USE_DISTUTILS=stdlib ./venv/Scripts/python.exe -m pip install -r requirements.txt` (see next row / §0) |
| `pip install -r requirements.txt` fails on `Failed to build 'hexdump'` / `AssertionError` in `_distutils_hack` | `python-evtx`'s `hexdump` sub-dependency hits a setuptools/distutils conflict on this Python 3.10 install | **Resolved 2026-08-15:** `SETUPTOOLS_USE_DISTUTILS=stdlib` env var on the install disables the conflicting hack (see §0) |
| `docker` / `docker info` fail with "command not found" (not a connection error) | Docker Desktop isn't installed on this machine at all | Install Docker Desktop from docker.com; until then, §1/§2/§6/§4's `/health` check and §9.4's `/mitre/techniques` check all work without it |
| `docker info` fails with a connection/pipe error (Docker *is* installed — `docker --version` works) | Docker Desktop is installed but its daemon isn't running/auto-started | Launch `Docker Desktop.exe` (Start Menu, or `C:\Program Files\Docker\Docker\Docker Desktop.exe`) and wait a few seconds for the daemon; confirmed fixed 2026-08-17 (see §3's resolution note) — it does not auto-start with Windows on this machine, so repeat each session |
| `POST /ingest` returns HTTP 500 with `psycopg2.OperationalError: connection ... port 5433 failed: Connection refused` in the server log | No live Postgres (Docker not running/installed) — same root cause as the `docker` rows above | Start Postgres per §3, or treat as expected on a machine without Docker; the route's own parse/validate logic is separately confirmed via §9.1's SQLite-backed automated test |
| `curl -F "file=@/tmp/foo.txt"` fails with `curl: (26) Failed to open/read local data from file/application` | This environment's `curl.exe` (native mingw64 build) only path-translates a POSIX path when it leads the argument; embedded after `-F file=@`, `/tmp/...` is passed through literally and Windows can't resolve it | Use a path relative to your shell's cwd, or `cygpath -w /tmp/foo.txt` to get a Windows path first (see §9.3) |
| `POST /incidents/{id}/explain` → `503 {"detail":"LLM call failed after 2 attempts: ... 429 RESOURCE_EXHAUSTED ... free_tier_requests"}` | Free-tier Gemini key hit its daily cap (20 requests/day for `gemini-3.7-flash`) — each `/explain` call costs 2 requests (draft + self-critique) | Wait for the daily quota reset (message includes a `retryDelay` hint), switch `.env`'s `LLM_PROVIDER` to `groq` (a Groq key is a valid alternative), or use a different free-tier Gemini key; don't re-run live-LLM smoke tests (§10.4/§11.3/§12.3) back-to-back in the same session (see §12.3). Fails fast (~15-30s, bounded by `llm_client.py`'s `timeout`/`max_retries` tuning, §22.8) with the real message — it no longer hangs for ~100s+ then masks the reason as a generic `500` (fixed 2026-08-21, §22.8) |
| `LLMProviderError: ... 503 UNAVAILABLE ... high demand` | Transient Gemini overload, unrelated to this project's code | Retry after a short wait; `llm_client.py` already retries once automatically before raising |
| `pytest` collection-errors with `ModuleNotFoundError: No module named 'langchain_groq'` (venv otherwise already set up) | `langchain-groq` was added to `requirements.txt` by the Day 10 Groq commit (`9cf6913`) after this venv was originally created, and the venv was never re-synced | `./venv/Scripts/python.exe -m pip install -r requirements.txt` — re-run this after every pull, not just on first setup (confirmed 2026-08-19) |
| `docker compose build backend` fails with `SSLError: CERTIFICATE_VERIFY_FAILED` fetching from `pypi.org`/`files.pythonhosted.org` | Same corporate/AV TLS interception as the `pip-system-certs` row above, but the container's bare Debian image has no access to Windows' trust store the way the host venv does | Already handled in `backend/Dockerfile` — the builder stage's `pip install` passes `--trusted-host pypi.org --trusted-host files.pythonhosted.org`. If it still fails, confirm you're on the same intercepted network (§22.6) |
| Tests hitting the LLM client make a real network call to Groq instead of using the test file's mocks | `.env`'s `LLM_PROVIDER` was left set to `groq` from an earlier manual-testing session; `tests/rag/test_llm_client.py` only mocks the Gemini (`ChatGoogleGenerativeAI`) branch, not `ChatGroq` | Set `LLM_PROVIDER=gemini` in `.env` (the project default) once you're done testing against Groq — confirmed as the fix 2026-08-20 |

---

## Out of scope for this guide

- Frontend testing (nothing built yet — Days 14+ per the 26-day roadmap).
- Rules-manager UI / `api/routes_rules.py` enable-disable endpoint (Pair 2 Day 17 — not yet built). Everything else through Pair 1 Day 13 — the ingest API, Sigma detection engine, 15 detection rules, alert persistence, incident grouping, severity scoring, MITRE technique validation, `GET /incidents`/`GET /incidents/{id}` with pagination, API key auth, rate limiting, and the backend Docker image — is done and covered, see §9/§12/§13/§14/§15/§18/§19/§21/§22.
- Pair 2's Day 13 tasks (LLM response caching, audit log, CI pipeline) — the teammates' own work, not covered by this guide.
- Chat history endpoint (`GET /incidents/{id}/chat`) and LLM call robustness/prompt refinement (Pair 2 Day 12 — not yet built). Hallucination spot-check (Day 10, `docs/research/hallucination-eval.md`) and the incident chat endpoint with source attribution (Day 11, §20) are done, alongside retrieval, the MITRE endpoint/validator scaffold, the explanation prompt template + LLM client, the explain_service retrieve→draft→self-critique pipeline, and the explain endpoint with source attribution + recommended response — see §8/§9/§10/§11/§17/§20. The Day 9 explain endpoint (§17) works against manually-inserted `Incident` rows in this guide's checks — Pair 1's incident grouping (§14) and read endpoints (§19) exist, but this guide hasn't re-verified the explain endpoint against a real grouped incident end-to-end (Docker/Postgres unavailable in this environment as of the last session that touched §17/§19.7 either way).
- The formal Testing Report (Volume 3 §9.5) — that's produced during Days 20–21 Integration & Testing, covering unit/integration/E2E coverage and RAG accuracy scoring across the whole system.
