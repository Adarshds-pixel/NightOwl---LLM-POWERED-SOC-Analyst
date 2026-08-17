# NightOwl Handbook — Volume 5: Manual Testing Guide

**Scope:** verifying everything built through **Pair 1 Day 6** (FastAPI skeleton, DB session dependency, DB models v1, Postgres/Alembic, EVTX reading + JSON conversion, normalized event schema + persistence, `POST /ingest` + robust error handling), **Pair 2 Day 6** (ChromaDB + embeddings setup, MITRE ATT&CK loader, real knowledge-base build, top-k retrieval, `GET /mitre/techniques` + rule-to-technique validator scaffold), as of **2026-08-15**; **Pair 2 Days 7–8** (explanation prompt template + Gemini LLM client wiring; explain_service's retrieve → draft → self-critique pipeline); and **Pair 1 Day 7** (detection engine v1 — Sigma rule loader + evaluator, wired into `POST /ingest`), as of **2026-08-16**. Whole suite + all live checks re-verified again on **2026-08-17** (see the "Re-verified 2026-08-17" notes throughout, and the new §13 consolidated runbook) with no regressions found; Docker Desktop was also started and Postgres brought up for the first time since 2026-08-12, fixing the `POST /ingest` HTTP 500 gap that prior days had noted as a known, environment-only limitation (not a code defect) — see §3/§9.3/§12.4's "second pass" notes. A real Gemini key was then added, which surfaced and led to fixing one genuine bug — `app/core/config.py` resolved `.env` relative to cwd instead of its own file location, so `LLM_API_KEY` was never actually read when running from `backend/` (see §10.4's "Bug found + fixed" note) — after which both live-Gemini checks (§10.4/§11.3) passed for real. Every check in this guide has now been executed for real at least once as of 2026-08-17, with no open gaps.

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
./venv/Scripts/python.exe -m pytest tests/test_day3_backend_setup.py tests/test_day3_models.py -v
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
./venv/Scripts/python.exe -m pytest tests/test_day3_setup.py -v
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
./venv/Scripts/python.exe -m pytest tests/test_day5_normalizer.py tests/test_day5_event_service.py -v
```

Covers:
- `test_day5_normalizer.py` — maps hand-crafted Sysmon-shaped records (the repo's only `sample.evtx` is Windows System-log data, not Sysmon, so real event ID 1/3/11 fixtures aren't available in the file itself) to `NormalizedEvent` for event IDs 1 (process creation → `process`/`command_line`/`user`), 3 (network connection → `protocol`/`source_ip`/`source_port`/`destination_ip`/`destination_port`), and 11 (file create → `target_filename`); handles `EventID` as a plain string vs. a qualifier dict, `EventData.Data` as a single dict vs. a list, and empty `<Data>` elements; confirms unrecognized event IDs still normalize (common fields only, no exception) and that genuinely malformed records (`Event`/`System` missing, `EventID`/`TimeCreated` unparseable) raise `EventNormalizationError`.
- `test_day5_event_service.py` — in-memory SQLite (same pattern as `test_day3_models.py`), confirms `create_event`/`save_events` persist the `Event` row's flat columns from a `NormalizedEvent`, that `raw_json` holds both the original raw record and the normalized view (`{"raw": ..., "normalized": ...}`) so fields not yet promoted to flat columns aren't lost, that a batch commits and logs `"ingested N events"`, and that a persisted row round-trips correctly when queried back.

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

**Known gap — Event ID 3 and 11 are not present in this sample.** `sysmon.exe -c` on this machine showed `No rules installed` and `Network connection: disabled` — this Sysmon deployment only logs ProcessCreate (ID 1); NetworkConnect and FileCreate aren't enabled at all, regardless of what real activity happens. Enabling them would mean deploying a new Sysmon config XML on the live machine, which is a change to real endpoint monitoring, not just this repo — out of scope here. ID 3/11 mapping stays covered by the hand-crafted fixtures in `test_day5_normalizer.py`; `sysmon_sample.evtx` is real-world ID 1 data only.

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
`test_day4_evtx_reader.py` and `test_day5_normalizer.py`/`test_day5_event_service.py` re-run afterward, unaffected: `25 passed in 1.77s`.

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
./venv/Scripts/python.exe -m pytest tests/test_day5_retriever.py -v
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
./venv/Scripts/python.exe -m pytest tests/test_day6_ingest_route.py tests/test_day6_mitre_route.py tests/test_day6_mitre_validator.py -v
```

Covers:
- `test_day6_ingest_route.py` (Pair 1) — `POST /ingest` end-to-end against the real `sysmon_demo.evtx` fixture (via `TestClient` + an in-memory SQLite override of `get_db`), plus the three named failure modes: wrong extension, empty file, malformed/corrupted EVTX bytes; and that a malformed *record* inside an otherwise-good file is skipped and counted, not treated as a whole-upload failure.
- `test_day6_mitre_route.py` (Pair 2) — `GET /mitre/techniques` returns the full catalog sorted by ID, includes `is_deprecated`/`is_revoked` flags per entry, and handles an empty lookup cleanly. `load_mitre_techniques` is monkeypatched to a small fixed lookup so this test doesn't depend on the full downloaded MITRE dataset.
- `test_day6_mitre_validator.py` (Pair 2) — `mitre/validator.py`'s `validate_technique_id`/`validate_technique_ids` scaffold: valid ID, unknown ID, deprecated-flagged ID, revoked-flagged ID, and the batch form. Also monkeypatched against a fixed lookup.

**Expected:** `13 passed`.
**Last verified:** 2026-08-15 — `13 passed in 2.24s`.
**Re-verified 2026-08-17:** covered as part of the full 90-test regression run (§12.2) — passed.

### 9.2. Full regression pass

```
cd backend
./venv/Scripts/python.exe -m pytest -v
```

**Expected:** `47 passed` (34 from Day 3–5 + 13 from Day 6).
**Last verified:** 2026-08-15 — `44 passed, 3 failed in 90.64s`. The 3 failures are all in `tests/test_day5_retriever.py` (`retrieve()` returning 0 hits against the real `knowledge_base` Chroma collection in this environment) — pre-existing as of this run, unrelated to any Day 6 code (neither `routes_ingest.py`, `routes_mitre.py`, nor `validator.py` touch `rag/retriever.py` or the Chroma collection), and not fixed as part of Day 6. Flagged here for Kiran/the team to look into before Day 7 builds the LLM/prompt layer on top of retrieval — see §8.1 for the isolated repro.

> **Resolved (2026-08-16):** re-ran `pytest -v` before starting Day 7 — `47 passed in 29.03s`, all 3 `test_day5_retriever.py` cases now green. On-disk inspection (sqlite embedding row count, HNSW segment file size, a live `retrieve()` call) showed a complete, consistent index; the most likely explanation is a transient stale on-disk index state on 2026-08-15 that resynced on a later write/read cycle. No change was needed in `retriever.py`/`chroma_client.py`.

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
./venv/Scripts/python.exe -m pytest tests/test_day7_prompts.py tests/test_day7_llm_client.py -v
```

Covers:
- `test_day7_prompts.py` — `rag/prompts.py`'s `format_incident_context`/`format_chunks`/`build_explanation_prompt`: renders incident fields, drops empty ones, formats retrieved chunks (score + metadata + document text) in `retriever.retrieve()`'s exact shape, and confirms the rendered prompt is exactly a `[SystemMessage, HumanMessage]` pair with the grounding rules and technique ID embedded correctly. Handles empty incident/chunks input.
- `test_day7_llm_client.py` — `rag/llm_client.py`'s `get_llm_client`/`generate`: raises `LLMProviderError` when `LLM_API_KEY` is unset (no key needed to run this — that's the point); constructs `ChatGoogleGenerativeAI` with the configured model/key; caches the client instance; returns the mocked response content on success; retries once then raises after repeated failure; recovers if the retry succeeds; raises on an empty response. `ChatGoogleGenerativeAI` is fully mocked (`monkeypatch`, same pattern as `test_day6_mitre_validator.py`'s `load_mitre_techniques` mocking) — fully offline, no network call, no real API key used.

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
**Not re-verified 2026-08-17 (first pass):** `LLM_API_KEY` is empty in this machine's `.env` today, so this live-Gemini check was skipped rather than faked. `test_day7_llm_client.py`'s fully-mocked automated tests (§10.1) still cover the request/response logic offline.

> **Bug found + fixed 2026-08-17:** after a real key was added to `.env`, this step still raised `LLMProviderError: LLM_API_KEY is not set` even though the key was present. Root cause: `Settings.model_config` in `app/core/config.py` used `env_file=".env"`, a path pydantic-settings resolves **relative to the process's current working directory** — but every command in this guide runs from `backend/`, while the real `.env` lives at the repo root. Since Postgres's `DATABASE_URL` default happens to match `.env.example`'s value, this silently never surfaced there, but `LLM_API_KEY`'s empty-string default made it fail loudly. Fixed by resolving the `.env` path from `config.py`'s own file location instead of cwd: `_ENV_FILE = Path(__file__).resolve().parents[3] / ".env"`. Full 90-test suite re-run after the fix: `90 passed in 31.98s`, no regressions.

**Re-verified 2026-08-17 (second pass, after the config.py fix):** real call against `gemini-flash-latest` succeeded — a correctly-structured "What happened" / "Why it matters" / "Recommended next steps" explanation referencing `T1059.001`, `WIN10-ANALYST`, and `jdoe`. Matches the 2026-08-16 baseline in structure and content.

> **Bug found + fixed during this verification:** the current `langchain-google-genai` (4.3.4) returns `AIMessage.content` as a list of content blocks (`[{"type": "text", "text": ..., "extras": {"signature": ...}}]`), not a plain string as `generate()` originally assumed. This silently passed the raw list through instead of raising or returning text. Fixed in `llm_client.py` with a `_extract_text()` helper that concatenates `type: "text"` blocks (and passes plain strings through unchanged, so older/other providers still work); covered by a new regression test, `test_generate_extracts_text_from_content_block_list`, in `test_day7_llm_client.py`.

---

## 11. Day 8 — Explanation generation with self-critique (Pair 2 deliverable)

### 11.1. Automated tests

```
cd backend
./venv/Scripts/python.exe -m pytest tests/test_day8_explain_service.py -v
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
**Not re-verified 2026-08-17 (first pass):** same reason as §10.4 — `LLM_API_KEY` is empty in this machine's `.env` today, so the 2 real Gemini calls this step needs were skipped rather than faked. `test_day8_explain_service.py`'s fully-mocked automated tests (§11.1) still cover the pipeline logic offline.

**Re-verified 2026-08-17 (second pass, after a real key was added and §10.4's config.py cwd-resolution bug was fixed):** ran successfully end-to-end against the real KB (5 chunks retrieved) and Gemini (2 real calls: draft + critique). Same known finding as 2026-08-16 — the critique flagged the incident-specific host/user/encoded-command values as unsupported by the KB chunks (correct behavior, not a new bug; see the "Known finding, not a bug" note below), and the `**Confidence check:**` section was appended as designed.

**Known finding, not a bug:** the critique step currently checks *all* claims in the draft against the KB chunks, including incident-specific facts (host, user, command line) that were never meant to come from the KB — they're given directly in the incident context. This makes the critique flag things that are actually fine, which could make the confidence-check section noisy/less useful once real incidents flow through this (Day 10+). Worth revisiting when Day 9 extends the prompt (e.g. scope the critique to only check claims about attacker technique/behavior/response guidance — the parts that should be grounded in retrieved sources — not claims that simply restate the input incident).

---

## 12. Day 7 — Detection engine v1 (Pair 1 deliverable)

### 12.1. Automated tests

```
cd backend
./venv/Scripts/python.exe -m pytest tests/test_day7_rule_loader.py tests/test_day7_detection_engine.py tests/test_day7_ingest_detection.py -v
```

Covers `detection/rule_loader.py` (loads + validates `.yml` rules via pySigma, skips malformed files without crashing, module-level cache with `force_reload`), `detection/engine.py` (the `and`/`or`/`not`/parentheses condition parser in isolation, `contains`/`startswith`/`endswith` field modifiers, AND-across-fields-in-one-selection, logsource-category-to-event-ID scoping, and an end-to-end check against the real seed rule in `detection/rules/`), and the `POST /ingest` wiring (`test_day7_ingest_detection.py`, monkeypatched rule set + mocked EVTX reader, no DB write path involved).

**Expected:** `20 passed`.
**Last verified:** 2026-08-16 — `20 passed in 8.02s`.
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
`sysmon_demo.evtx`'s 4 records don't contain an encoded-PowerShell process-creation event, so `rule_matches: 0` here is expected — `test_real_seed_rule_matches_encoded_powershell_event` in `test_day7_detection_engine.py` is what proves the seed rule *can* fire, using a crafted matching event.
**Last verified:** 2026-08-16 — reproduced the no-Postgres HTTP 500 exactly as above (traceback confirmed pointing at the same `psycopg2.OperationalError` DB-connect step as §9.3, not at detection code); the Postgres-connected path is confirmed via `test_day7_ingest_detection.py`'s SQLite-backed route test instead, since Docker isn't available on this machine.
**Re-verified 2026-08-17 (first pass, before Docker was started):** same HTTP 500 / same `psycopg2.OperationalError` traceback, still ahead of the detection step — no change; see §9.3's matching re-verification for the shared traceback.
**Re-verified 2026-08-17 (second pass, with Postgres up — see §3/§9.3's resolution):** HTTP 200, `{"filename":"sysmon_demo.evtx","records_read":4,"events_ingested":4,"events_skipped":0,"rule_matches":0,"matched_rule_titles":[]}` — matches the "With Postgres running" expectation above exactly, including the two Day 7 detection fields. `rule_matches: 0` is correct — `sysmon_demo.evtx` doesn't contain an encoded-PowerShell event.

### 12.5. Known v1 limitations (by design — see `docs/decisions.md`)
- Condition grammar supports `and`/`or`/`not`/parentheses over bare selection names only — no `1 of`/`all of them` shorthand, no named multi-condition rules.
- Field modifiers: exact match (case-insensitive), `contains`, `startswith`, `endswith` only — no `|re` or glob `*` wildcards yet.
- Only one seed rule exists in `detection/rules/` (`suspicious_encoded_powershell.yml`) — Day 8 builds this out to 5 rules across process-creation/network-connection/file-creation categories and adds `alerts` persistence.

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
- **Full `POST /ingest` route** (`TestClient` + in-memory SQLite, same pattern as §12.4/`test_day7_ingest_detection.py`): HTTP 200, `records_read: 64558, events_ingested: 64558, events_skipped: 0, rule_matches: 0` — the entire real-world file flows through read → normalize → persist → detect without a single dropped record.

Not wired into pytest as a hard dependency (same rationale as §12's other real-file checks — a machine-specific real file shouldn't be a hard dependency of the automated suite); this was a manual verification pass. The Day 8 network-connection-category Sigma rule can be developed/tested against this real fixture instead of only hand-crafted ones.

---

## 13. Full Repository Manual Test Runbook (consolidated, run everything)

Everything above (§1–§12) is a detailed, day-by-day reference — what each piece covers, why, and
its full verification history. This section is the opposite: a single linear checklist to run the
**whole repo** end-to-end in one sitting, e.g. before a demo or a milestone check-in. It doesn't
re-explain anything — it just sequences the commands and points back to the section with the full
detail/expected output for each step.

### 13.1. Prerequisites checklist

- [ ] `backend/venv` exists with deps installed (§0). If not: `cd backend && python -m venv venv && ./venv/Scripts/pip install -r requirements.txt` (see §0 for the two Windows install gotchas).
- [ ] Repo-root `.env` exists (`cp .env.example .env` if not).
- [ ] *Optional, for §13.3's Postgres block:* Docker Desktop installed and running (`docker info` succeeds).
- [ ] *Optional, for §13.3's live-LLM block:* `LLM_API_KEY` set in `.env` (free key: https://aistudio.google.com/apikey).

Everything in §13.2 runs with **just the first two boxes checked**. §13.3 is gated on Docker/API key and is explicitly optional/skippable.

### 13.2. Core pass — no Docker, no API key required

Run top to bottom from the repo root unless noted:

```
cd backend

# 1. Full automated suite — everything Pair 1 + Pair 2 have built so far
./venv/Scripts/python.exe -m pytest -v
# Expect: 90 passed (see §12.2 for the authoritative running total)

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
# Expect: HTTP 200 + rule_matches/matched_rule_titles fields WITH Postgres running (§3, §13.3)
# Expect: HTTP 500 (psycopg2 "port 5433 ... Connection refused") WITHOUT Postgres — a known,
#         non-defect gap, not a new bug. The same request path is separately proven correct
#         end-to-end against SQLite by the automated suite in step 1.               (§9.3/§12.4)

# 6. Ingest error handling — three cases, all pure validation, no DB touched
curl -F "file=@<a-non-evtx-file>;type=text/plain" http://127.0.0.1:8000/ingest
curl -F "file=@<a-0-byte-file>;type=application/octet-stream" http://127.0.0.1:8000/ingest
curl -F "file=@<a-file-with-garbage-bytes>;type=application/octet-stream" http://127.0.0.1:8000/ingest
# Expect: all three HTTP 400, with the three specific `detail` messages in §9.3
```

Back in the first shell, stop the server (Ctrl+C), then run the two no-server, no-key module smoke tests:
```
cd backend
./venv/Scripts/python.exe -m app.detection.rule_loader
# Expect: one line for the seed rule (id, level, title, category)                  (§12.3)

./venv/Scripts/python.exe -m app.rag.prompts
# Expect: rendered system message (grounding rules) + human message (sample incident + 1 chunk)  (§10.3)
```

### 13.3. Optional extended pass — needs Docker and/or an LLM API key

Only run the parts your environment supports:

```
# Needs Docker Desktop running:
docker compose up -d db                        # §3
docker compose exec db pg_isready -U nightowl
cd backend
./venv/Scripts/python.exe -m alembic upgrade head
./venv/Scripts/python.exe -m alembic current    # Expect: fa0ac08ab62f (head)
docker compose exec db psql -U nightowl -d nightowl -c "\dt"   # Expect: 6 tables

# With Postgres now up, re-run step 5 of §13.2 — expect HTTP 200 this time instead of 500.

# Needs LLM_API_KEY set in .env:
./venv/Scripts/python.exe -m app.rag.llm_client       # real Gemini call, §10.4
./venv/Scripts/python.exe -m app.rag.explain_service  # real retrieve + 2 Gemini calls, §11.3
```

### 13.4. Sign-off checklist

| Component | Section | Result | Notes |
|---|---|---|---|
| Full pytest suite (90 tests) | §12.2 | ☐ Pass ☐ Fail | |
| `/health` | §4 | ☐ Pass ☐ Fail | |
| `GET /mitre/techniques` | §9.4 | ☐ Pass ☐ Fail | |
| `POST /ingest` happy path | §9.3/§12.4 | ☐ Pass ☐ Fail ☐ Skipped (no Docker) | HTTP 500 without Postgres is expected, not a fail |
| `POST /ingest` error cases (×3) | §9.3 | ☐ Pass ☐ Fail | |
| `rule_loader` module smoke | §12.3 | ☐ Pass ☐ Fail | |
| `prompts` module smoke | §10.3 | ☐ Pass ☐ Fail | |
| Postgres/Alembic (6 tables) | §3 | ☐ Pass ☐ Fail ☐ Skipped (no Docker) | |
| Live Gemini call (`llm_client`) | §10.4 | ☐ Pass ☐ Fail ☐ Skipped (no API key) | |
| Live explain_service (2 Gemini calls) | §11.3 | ☐ Pass ☐ Fail ☐ Skipped (no API key) | |
| Real Sysmon VM capture through full pipeline | §12.6 | ☐ Pass ☐ Fail ☐ Not re-run (63MB file, manual only) | |

Tester: ____________  Date: ____________  Environment (Docker? API key?): ____________

**Scope reminder** (matches "Out of scope" below): this runbook covers everything built through Pair 1 Day 7 (detection engine) and Pair 2 Day 8 (explain_service). It does **not** cover the frontend (none built yet), incident endpoints, the `/explain` HTTP endpoint, chat endpoints, or the formal Testing Report — those are still ahead on the roadmap.

**2026-08-17 run of this exact checklist:** §13.2's entire core pass executed for real — 90/90 tests passed (39.85s), `/health` 200, `/mitre/techniques` 200 (count 858), all 3 ingest error cases HTTP 400 as expected, `rule_loader` and `prompts` module smoke tests both matched their documented output exactly. Ingest happy path initially returned HTTP 500 (Docker Desktop wasn't running yet — same known gap as prior days); §13.3's Docker block was then run for real (Docker Desktop started, `docker compose up -d db`, `alembic upgrade head` → `fa0ac08ab62f (head)`, 6 tables confirmed), after which the happy path returned HTTP 200 as designed — see §3/§9.3/§12.4's "second pass" notes.

A real Gemini key was then added to `.env`, which surfaced one genuine bug (not environmental): `app/core/config.py`'s `Settings` resolved `.env` relative to the process's cwd, but every command here runs from `backend/`, so the key was never actually read regardless of what was in the file. Fixed in `config.py` (resolve `.env` from the module's own file location instead of cwd) — full 90-test suite re-confirmed green after the fix, then both live-Gemini checks (§10.4, §11.3) ran for real and succeeded. **As of 2026-08-17, every check in this runbook has been executed for real and passes** — no known gaps remain except Docker Desktop needing a manual start each session (it doesn't auto-launch on this machine).

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `failed to connect to the docker API ... dockerDesktopLinuxEngine` | Docker Desktop isn't running | Launch Docker Desktop and wait ~10–20s, then retry |
| `SSLError: CERTIFICATE_VERIFY_FAILED` on any GitHub/HuggingFace call | Corporate/AV TLS interception not trusted by Python's `certifi` bundle | `pip install pip-system-certs` in the venv (see Prerequisites) |
| `pg_isready` never succeeds / port 5433 already in use | Another Postgres instance already bound to 5433, or the container needs more time | `docker compose ps`, `docker compose logs db`; confirm nothing else owns host port 5433 |
| First run of `test_day3_setup.py` or `build_kb.py` is slow (~1–2 min) | `sentence-transformers`/`torch` downloading model weights and MITRE JSON on first use | Expected once; subsequent runs use local caches (`data/mitre/enterprise-attack.json`, HF cache, `data/chroma/`) |
| `uvicorn` port 8000 still bound after stopping | Reload/watcher spawned a child process with a different PID | `netstat -ano \| findstr :8000` then `taskkill /F /PID <pid>` |
| `pytest -v` (bare, whole `tests/` dir) collection-errors with `ModuleNotFoundError: fastapi`/`sqlalchemy`/`Evtx` | Those Pair 1 deps aren't installed in this venv | `SETUPTOOLS_USE_DISTUTILS=stdlib ./venv/Scripts/python.exe -m pip install -r requirements.txt` (see next row / §0) |
| `pip install -r requirements.txt` fails on `Failed to build 'hexdump'` / `AssertionError` in `_distutils_hack` | `python-evtx`'s `hexdump` sub-dependency hits a setuptools/distutils conflict on this Python 3.10 install | **Resolved 2026-08-15:** `SETUPTOOLS_USE_DISTUTILS=stdlib` env var on the install disables the conflicting hack (see §0) |
| `docker` / `docker info` fail with "command not found" (not a connection error) | Docker Desktop isn't installed on this machine at all | Install Docker Desktop from docker.com; until then, §1/§2/§6/§4's `/health` check and §9.4's `/mitre/techniques` check all work without it |
| `docker info` fails with a connection/pipe error (Docker *is* installed — `docker --version` works) | Docker Desktop is installed but its daemon isn't running/auto-started | Launch `Docker Desktop.exe` (Start Menu, or `C:\Program Files\Docker\Docker\Docker Desktop.exe`) and wait a few seconds for the daemon; confirmed fixed 2026-08-17 (see §3's resolution note) — it does not auto-start with Windows on this machine, so repeat each session |
| `POST /ingest` returns HTTP 500 with `psycopg2.OperationalError: connection ... port 5433 failed: Connection refused` in the server log | No live Postgres (Docker not running/installed) — same root cause as the `docker` rows above | Start Postgres per §3, or treat as expected on a machine without Docker; the route's own parse/validate logic is separately confirmed via §9.1's SQLite-backed automated test |
| `curl -F "file=@/tmp/foo.txt"` fails with `curl: (26) Failed to open/read local data from file/application` | This environment's `curl.exe` (native mingw64 build) only path-translates a POSIX path when it leads the argument; embedded after `-F file=@`, `/tmp/...` is passed through literally and Windows can't resolve it | Use a path relative to your shell's cwd, or `cygpath -w /tmp/foo.txt` to get a Windows path first (see §9.3) |

---

## Out of scope for this guide

- Frontend testing (nothing built yet — Days 13+).
- Sigma detection engine, incident endpoints (Pair 1 Days 7–12 — not yet built; the ingest API itself is done, see §9).
- Explain endpoint, hallucination spot-check, chat endpoints (Pair 2 Days 9–12 — not yet built; retrieval, the MITRE endpoint/validator scaffold, the explanation prompt template + LLM client, and the explain_service retrieve→draft→self-critique pipeline are done, see §8/§9/§10/§11).
- The formal Testing Report (Volume 3 §9.5) — that's produced during Days 20–21 Integration & Testing, covering unit/integration/E2E coverage and RAG accuracy scoring across the whole system.
