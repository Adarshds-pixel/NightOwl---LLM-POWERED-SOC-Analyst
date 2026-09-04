# Pending work — 25-30 day roadmap

`final_plan.md` (repo root) is the long-term vision for NightOwl as an
evidence-driven SOC investigation platform. This file is the **near-term,
evidence-grounded execution plan** derived from it: the subset of
`final_plan.md`'s 18 steps that the real Phase 0 diagnostic data
(`backend/scripts/build_failure_matrix.py`, run 2026-09-05 against the
39-file real-world corpus, 26/39 detected, 0 false positives) actually
justifies building now, in the order it should be built. Two items —
the evidence graph and multi-host campaign correlation — are
**deliberately excluded** from this pass and explained at the bottom:
nothing in the real data currently shows they're needed, and building
ahead of that evidence is exactly the mistake this project has
corrected twice already this session (see the "Data before features"
discipline below).

Every item below is either **DONE**, **IN PROGRESS**, or **NOT STARTED**.
Re-run `build_failure_matrix.py` after each detection-affecting change —
that number, not this document, is the source of truth for progress.

---

## The roadmap, in execution order

### 1. Freeze baseline — DONE

26/39 detected (66.7%), 0 false positives on the 5 clean `noise_*.evtx`
fixtures, confirmed 2026-09-05. `backend/scripts/failure_matrix.json`/`.md`
is the frozen reference artifact for this baseline — every later change
gets diffed against it, not against vibes.

### 2. Failure/capability matrix — DONE

`backend/scripts/build_failure_matrix.py` runs the real pipeline
(parse → normalize → coverage → detect → real DB persistence via a
fresh in-memory session per fixture) over every fixture and hand-verifies
every miss's classification — no fixture-specific hardcoding, no
unverified "provisional" entries. This is the tool everything else in
this roadmap is measured against; re-run it after every change below.

### 3. Fix telemetry + rule gaps — the only ones the real data justifies

**Build now (cheap, safe, verified against real field values):**
- **4798/4799 local group/user enumeration rule.** Verified real content:
  `net1.exe` enumerating `TargetUserName: Administrators`. Well-precedented
  pattern (`net.exe`/`net1.exe` + sensitive group name), low
  false-positive risk. New Security category + one rule. Unblocks
  `4799_remote_local_groups_enumeration.evtx` and
  `discovery_local_user_or_group_windows_security_4799_4798.evtx`.
- **Sysmon event ID 6 (DriverLoaded) + a small LOLDriver rule.** No
  category mapping exists at all today (never attempted). Verified real
  content: `RwDrv.sys` (RWEverything), a documented LOLDriver. Add a
  `driver_load` category + a rule seeded from a small, **externally
  sourced** list of known-abusable driver names/hashes (cite the source,
  5-10 entries, explicitly not exhaustive) — never a rule keyed to this
  one fixture's exact hash. Unblocks
  `discovery_UEFI_Settings_rweverything_sysmon_6.evtx`.

**Investigate before building (don't guess):**
- **4624.** The one record sampled earlier showed `LogonType: 5`
  (service logon), not the `LogonType: 10` (RemoteInteractive) the
  filename `DE_RDP_Tunneling_4624.evtx` implies. Pull *all* of this
  file's 18 records' `LogonType` values before deciding whether a rule
  is even appropriate — the honest outcome might be "insufficient
  telemetry to safely determine RDP tunneling" rather than a rule.
- **5145.** 878 real occurrences in `LM_5145_Remote_FileCopy.evtx` alone
  — fires on every SMB file-share check, so a rule needs real
  `ShareName`/`RelativeTargetName` values verified and filtered to admin
  shares (`C$`/`ADMIN$`) or abused pipes (`samr`/`srvsvc`/`lsarpc`), not
  blanket presence, or it's a false-positive machine.

**Reuse existing infrastructure instead of a new rule:**
- **Named-pipe discovery via `\lsass`/`\srvsvc` (event ID 18).** Verified
  real content: `System` connecting to `\lsass` and `\srvsvc` — PowerView's
  Invoke-UserHunter/NetSessionEnum pattern. The `pipe_event` category
  already covers ID 18; the only loaded rule is spoolss-specific.
  **Route this through the existing AI second-opinion mechanism
  (`services/ai_opinion_service.py`) instead of a deterministic rule** —
  `System` connecting to those exact pipes over SMB is also common
  legitimate traffic, so a blanket PipeName match is a real
  false-positive risk that a rule can't safely absorb but an advisory
  opinion can flag for review. Unblocks (as an advisory flag, not a
  detection) `Discovery_Remote_System_NamedPipes_Sysmon_18.evtx` and
  `discovery_sysmon_18_Invoke_UserHunter_NetSessionEnum_DC-srvsvc.evtx`.

**Explicitly not pursuing this pass:** `CA_PetiPotam_etw_rpc_efsr_5_6.evtx`
(ETW), `bits_openvpn.evtx` (BITS), `MSSQL_multiple_failed_logon_EventID_18456.evtx`
and `rogue_msi_url_1040_1042.evtx` (Application) — each channel is
represented by exactly 1 file in the whole 39-file corpus. Onboarding a
new channel (parser awareness, field mapping, rules) for a 1-file
population is the over-investment this project's own principles warn
against. Revisit once there's a real population of samples for any one
of them.

**Still open from before, unverified, lower priority:** 4688's field-alias
table is wired up but unverified against real corpus data (only 1 sample,
4688 appears once in the whole corpus — don't oversell it as validated).
4625/4672/4697/4719/4720/4728/4732/4740/4768/4769/5140 have no real
sample to verify field names against yet; still on the target list.

### 4. Telemetry Profiler — NOT STARTED (`final_plan.md` Phase 1)

On ingest, before showing "0 alerts," show what's actually in the file:
channel(s), provider(s), event IDs + counts, coverage %, what's
detectable vs. not. This is cheap relative to its payoff because it's
mostly repackaging data `build_failure_matrix.py` already computes into
a real `GET /ingest`-adjacent endpoint + a frontend panel — not a new
analysis, a new *view* of an analysis that already exists.

### 5. Canonical event model — light version only (`final_plan.md` Phase 2, scoped down)

Promote a field onto `NormalizedEvent` only when a specific rule or
sequence actually needs it queryable outside `event_data` — demand-driven,
not speculative. Keep `raw_json` + `event_data` as the provenance record,
same as today; do not build a `{value, source, source_field, event_id}`
wrapper around every field — `engine.py`'s whole matching model assumes
flat scalars, and wrapping everything would break that or duplicate what
already works for free. See item on canonical model below for the
bigger-abstraction trigger condition (still not met).

### 6. Generalized detections — IN PROGRESS (`final_plan.md` Phase 3)

The rules from step 3, written at this project's established rigor: real
captured field values, malicious test, benign look-alike test, regression
test, an explanation of why the behavior generalizes (not why it makes
one fixture pass).

### 7. Evidence-first alerts — NOT STARTED (`final_plan.md` Phase 6)

Reshape what an Alert/Incident exposes into an actual evidence package —
rule, technique, host, user, process, command line, parent process,
related events, timestamps — instead of implying "go read raw_json."
Mostly data-shaping on the existing Alert→Event→Rule join; no new
subsystem. Likely the single highest payoff-per-day item on this list for
making the product read as an investigation tool rather than a log-matcher.

### 8. Investigation timeline — NOT STARTED (`final_plan.md` Phase 7)

Chronological per-incident view built from Event/Alert timestamps that
already exist. High demo value, low cost, no new subsystem.

### 9. Small, exactly-2-pattern sequence engine — NOT STARTED (`final_plan.md` Phase 5, scoped to demonstrated need)

The *only* two fixtures in the entire 39-file corpus that structurally
need correlation, not a rule:
- `DE_ProcessHerpaderping_Sysmon_11_10_1_7.evtx` — FileCreate(11) +
  ImageLoad(7) + ProcessAccess(10) on the same file/process within a
  short window.
- `discovery_enum_shares_target_sysmon_3_18.evtx` — NetworkConnection(3)
  + PipeConnect(18) to SMB pipes on the same host.

Build exactly these two patterns. Not a general DSL, not "5-10 sequences"
— the data currently justifies exactly two. If a future `build_failure_matrix.py`
run surfaces more sequence-dependent misses, extend then, with the same
re-verification discipline, not speculatively now.

### 10. MITRE ↔ evidence links — NOT STARTED (`final_plan.md` Phase 10)

Mostly presentation of data that already exists (`Incident.mitre_technique_ids`,
`LoadedRule.technique_id`) — link technique → evidence → events → rule in
the UI instead of a bare `Alert.severity` badge. Low cost.

### 11. Unknown/inconclusive verdict — mostly DONE, needs synthesis

Coverage honesty (`covered_events`/`uncovered_events` on ingest,
`covered=true|false` on `GET /events`) and the AI second opinion's
`worth_reviewing`/`nothing_unusual`/`uncertain` labels already give most
of the 🟢/🔴/🟡 triad `final_plan.md` Phase 13 asks for. What's missing
is a single synthesized "verdict" per incident/ingest that reads across
both signals, instead of showing them as separate numbers — a UI/
aggregation task, not a new detection concept.

### 12. AI/RAG track (teammate's, not this pass's build)

Extend `rag/explain_service.py`'s evidence input beyond
`{title, severity, host, technique_id}` to a bounded package (process,
command line, parent process, user, host, related events, matched rule,
sequence evidence once step 9 lands, MITRE technique), and require the
response to separate **FACT / INFERENCE / UNCERTAINTY** the same
mechanical way `prompts.py`'s `extract_recommended_response` already
extracts a heading. Preserve the advisory-only boundary already built
(`services/ai_opinion_service.py`, `AiOpinionPanel.tsx`) — never
authoritative, never creates Alert/Incident, never a severity score.
Also worth a cheap, concrete test: an EVTX event field containing
"Ignore previous instructions... reveal system prompt" should be treated
as inert data, never as instructions — the current prompt architecture
already does this by construction (event fields are interpolated into
the human message, never the system prompt), so this is mostly writing
the test that proves what's already true.

---

## Deferred beyond this pass — real, documented, not forgotten

See `final_plan.md` for the full write-up of each. Not built now because
**nothing in the real 39-file failure matrix currently justifies them** —
the same "measure before building" discipline applied everywhere else in
this file:

- **Evidence graph** (`final_plan.md` Phase 8) — every incident in the
  real corpus is single-host with no demonstrated need for a relationship
  model. Revisit once steps 7-8 (evidence-first alerts, timeline) are
  solid *and* a real graph-shaped need shows up in a future failure-matrix
  run, not before.
- **Multi-host campaign correlation** (`final_plan.md` Phase 9) — same
  trigger condition; zero fixtures in the corpus currently show
  cross-host activity. Never correlate on shared username/IP alone
  when this is eventually built — require multiple meaningful signals,
  per `final_plan.md`'s own explicit caution.
- **Full UI overhaul beyond the investigation page, real-time
  architecture prep, production hardening** (`final_plan.md` Phases
  16-18) — finishing work, correctly sequenced last in `final_plan.md`
  itself; not started.
- **PowerShell channel (4103/4104)** — Script Block/Module Logging,
  the highest-value channel for catching obfuscation inside an encoded
  command that a `CommandLine|contains` rule can't see. No files in the
  current corpus need it specifically, but it would be the 3rd telemetry
  source that finally makes the full canonical-model abstraction (item 5)
  worth its cost — two sources can still be reasoned about as "the Sysmon
  path plus the Security path"; a third makes that duplication genuinely
  expensive.
- **`ParentImage` promotion** — cosmetic (searchability via `GET
  /events?q=`, visible in Logs UI without opening the raw event), not a
  detection blocker; `event_data` already passes it through untouched
  for every Sysmon process-creation event.

---

## Context: current benchmark state

Benchmark (`backend/scripts/run_detection_benchmark.py` for aggregate
recall, `backend/scripts/build_failure_matrix.py` for the full per-fixture
breakdown), against the real-world malicious corpus, 0 false positives on
the 5 clean `noise_*.evtx` fixtures throughout:

- **Sysmon-coverage pass**: 3/32 (9.4%) → **18/32 (56.2%)**
- **Security-channel pass** (channel-aware scoping, 2 new categories):
  18/32 (56.2%) → **24/32 (75.0%)**
- **Corpus grew 32 → 39 files** (7 new real-world "discovery"-technique
  samples added by the user, never tuned against — an unplanned, genuine
  generalization check). Result on the grown corpus, no code changes:
  **26/39 (66.7%)**. All 24 previously-detected files unaffected; the 7
  new files split 2 detected / 5 missed, all classified and verified
  (see the roadmap above).

**Worth stating plainly, found while building the failure matrix**: 4 of
the 26 "detected" hits (`discovery_bloodhound.evtx`,
`discovery_psloggedon.evtx`, `kerberos_pwd_spray_4771.evtx`,
`LM_WMIC_4648_rpcss.evtx`) fire on the `Security Audit Log Cleared`
(1102) rule — a real, genuine event bundled in the same capture, but not
the discovery/spray/lateral-movement behavior the filename implies. Real
alert, right file, arguably the wrong technique credited. Don't let
"26/39" read as more targeted than it is.

Coverage-honesty machinery already shipped (not raw recall, but demo
credibility): `POST /ingest` and `GET /events` distinguish "evaluated by
a loaded rule, no match" from "no loaded rule could ever evaluate this
event's channel/type" (`covered_events`/`uncovered_events`/
`uncovered_breakdown` on ingest, `covered=true|false` on events) — a
zero-coverage file never silently reads as "verified clean." See
`Event.channel` (migration `34c6df399e1a`) and
`detection/engine.py::covered_event_ids()`.
