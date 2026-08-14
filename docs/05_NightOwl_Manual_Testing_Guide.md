# NightOwl Handbook — Volume 5: Manual Testing Guide

**Scope:** verifying everything built through **Pair 1 Day 5** (FastAPI skeleton, DB session dependency, DB models v1, Postgres/Alembic, EVTX reading + JSON conversion, normalized event schema + persistence) and **Pair 2 Day 3–4** (ChromaDB + embeddings setup, MITRE ATT&CK loader, real knowledge-base build), as of **2026-08-14**.

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

---

## 5. Real knowledge-base build (Pair 2 Day 4 deliverable)

```
cd backend
./venv/Scripts/python.exe scripts/build_kb.py
```

Downloads/parses the MITRE dataset, chunks all non-deprecated/non-revoked techniques plus the 5 playbooks under `data/knowledge_base/playbooks/`, embeds them with the project's own `sentence-transformers` wrapper (not Chroma's default embedding function), and upserts into the `knowledge_base` Chroma collection.

**Expected:** a summary line like `MITRE techniques: N processed, M skipped (deprecated/revoked)`, `Playbooks: 5 processed`, and a final `Upserted <count> chunks into Chroma collection 'knowledge_base' (<count> total in collection)`.
**Last verified:** 2026-08-12 — 697 techniques processed, 161 skipped (deprecated/revoked), 5 playbooks processed, 1888 total chunks upserted.

---

## 6. Full regression pass

Once Postgres is up and the MITRE/embedding caches are warm:
```
cd backend
./venv/Scripts/python.exe -m pytest -v
```

**Expected:** all tests pass together (31 as of Day 5 — 6 from Day 3, 4 from Day 4, 21 from Day 5).
**Last verified:** 2026-08-14 — `31 passed in 41.69s`.

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

### 7.1. Real Sysmon sample (`data/sample_logs/sysmon_sample.evtx`)

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

**Planned future method for real ID 3 (not built yet — Path A, deferred):**
1. Clean Windows VM/sandbox with no conflicting AV.
2. Install standalone Sysinternals `Sysmon64.exe`.
3. Minimal config enabling only `ProcessCreate` + `NetworkConnect` + `FileCreate`.
4. Generate the same kind of controlled/harmless test activity used here.
5. Capture, then validate through NightOwl's existing `evtx_reader.py` + `normalizer.py` (no code changes expected).
6. Host machine (this laptop) stays untouched throughout — the VM is fully separate.

This is scoped as a standalone future task, not attempted as part of Day 5.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `failed to connect to the docker API ... dockerDesktopLinuxEngine` | Docker Desktop isn't running | Launch Docker Desktop and wait ~10–20s, then retry |
| `SSLError: CERTIFICATE_VERIFY_FAILED` on any GitHub/HuggingFace call | Corporate/AV TLS interception not trusted by Python's `certifi` bundle | `pip install pip-system-certs` in the venv (see Prerequisites) |
| `pg_isready` never succeeds / port 5433 already in use | Another Postgres instance already bound to 5433, or the container needs more time | `docker compose ps`, `docker compose logs db`; confirm nothing else owns host port 5433 |
| First run of `test_day3_setup.py` or `build_kb.py` is slow (~1–2 min) | `sentence-transformers`/`torch` downloading model weights and MITRE JSON on first use | Expected once; subsequent runs use local caches (`data/mitre/enterprise-attack.json`, HF cache, `data/chroma/`) |
| `uvicorn` port 8000 still bound after stopping | Reload/watcher spawned a child process with a different PID | `netstat -ano \| findstr :8000` then `taskkill /F /PID <pid>` |

---

## Out of scope for this guide

- Frontend testing (nothing built yet — Days 13+).
- Sigma detection engine, ingestion API, incident endpoints (Pair 1 Days 6–12 — not yet built).
- RAG retrieval/generation/chat endpoints (Pair 2 Days 5–12 — not yet built).
- The formal Testing Report (Volume 3 §9.5) — that's produced during Days 20–21 Integration & Testing, covering unit/integration/E2E coverage and RAG accuracy scoring across the whole system.
