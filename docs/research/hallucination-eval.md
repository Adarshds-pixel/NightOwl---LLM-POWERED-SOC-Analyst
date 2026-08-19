# Day 10 Hallucination Spot-Check (Pair 2)

Manual verification of 10 real `POST /incidents/{id}/explain` calls (`backend/app/rag/explain_service.py`'s
retrieve → draft → self-critique pipeline) against known ground truth, per the roadmap's Day 10 task.
No incident fixtures/seed data existed yet, so — following Pair 1's own precedent for the same
situation (manual testing guide §13.4/§14.4) — 10 Sysmon-shaped records were crafted, one matching
each of the 10 real Sigma rules in `backend/app/detection/rules/*.yml`, and run through the actual
`/ingest → detect → group → severity` pipeline against real Postgres (only `read_records_as_dicts`
mocked; rules, detection engine, incident grouping, and severity scoring are all real). Each
resulting incident was then explained for real. Crafting the incidents ourselves gives an exact,
known ground truth (rule/technique/host/command) to check every generated claim against — a
stronger check than eyeballing a real incident where the "true" cause is itself just an educated
guess.

**Provider note:** run against **Groq** (`openai/gpt-oss-120b`), not the project's default Gemini —
Gemini's free tier caps at 20 requests/day and this spot-check alone needs 20 (10 incidents × 2
calls each: draft + self-critique). `llm_client.py` now picks the provider via `LLM_PROVIDER`
(`app/core/config.py`); Gemini remains the default, this run only set `LLM_PROVIDER=groq` locally.

Reproduce with:
```
docker compose up -d db
cd backend
./venv/Scripts/python.exe -m alembic upgrade head
./venv/Scripts/python.exe scripts/hallucination_spot_check.py
```
Full request/response data from this run is saved at
`backend/scripts/hallucination_spot_check_output.json`.

## Call A — real capture, sanity check

`sysmon_vm_capture.evtx` (64,558 real records) was ingested unmocked. **Result: `rule_matches: 0`,
`incident_ids: []`** — consistent with §13.5 of the manual testing guide, which already established
this capture is clean. No incident to spot-check here; it's included as a real-data false-positive
check, not one of the 10.

## Call B — 10 crafted incidents

All 10 crafted records matched their intended rule 1:1 and became 10 distinct incidents
(`rule_matches: 10`, `incident_ids: [3..12]`, one per host `SPOTCHECK-01`..`10`). Severity scoring
(`severity_service.compute_severity`) worked as documented — e.g. a `high` rule (T1059.001) whose
`execution` tactic carries a weight of 1 was correctly bumped to `critical` (4+1=5, capped).

## The 10 spot-checks

For each: does the `explanation` state only facts consistent with the crafted incident + retrieved
`sources`? Did `critique` (the self-critique pass) catch it? Note: `critique` fires on *any* claim
not verbatim in the retrieved chunks — including the incident's own `host` field, which is legitimate
context, not a hallucination. That happened on **all 10** runs and is not counted as a real finding
below; only claims beyond that are.

| # | Rule / Technique | Ground truth | Self-critique caught (beyond host) | Real issue found |
|---|---|---|---|---|
| 1 | Suspicious Encoded PowerShell Command / T1059.001 | `powershell.exe -enc <b64>` | Yes — invented severity rationale ("rarely used in normal admin work"), "full compromise" escalation | Minor: unsupported severity rationale, not a factual error |
| 2 | PowerShell Execution Policy Bypass / T1059.001 | `powershell.exe -nop -ExecutionPolicy Bypass -File ...` (**no** `-enc`/`-EncodedCommand`) | Partially — flagged "bypass execution policy" framing as unsupported | **Yes — real hallucination, missed by critique.** Draft states the process "used an encoded-command flag (e.g., `-EncodedCommand` or `-enc`)". The crafted command line has neither; retrieval pulled the only available T1059.001 playbook (written for the *encoded-command* scenario, since the KB has no execution-policy-bypass-specific playbook) and the LLM imported that playbook's specific technical detail as if it applied here. Self-critique challenged the "bypass" framing but not this more concrete, checkable claim. |
| 3 | Certutil Download via urlcache/split / T1105 | `certutil.exe -urlcache -split -f http://185.220.101.5/... ` | Yes — thorough: flagged invented Event IDs 4688/5145, "quarantine VLAN," "search for lateral movement (T1570)" | Ungrounded elaboration, correctly self-flagged |
| 4 | Suspicious Network Connection from LOLBin / T1071.001 | `powershell.exe` → `185.220.101.5:443` | Host only | Clean — every claim (non-browser process, IP-literal destination, beaconing) traces to the retrieved playbook |
| 5 | Suspicious Executable Written to Public/Temp / T1105 | `C:\Users\Public\update.exe` | Yes — thorough: flagged "execute for further control/lateral movement/exfiltration," sandbox/quarantine specifics, T1570 reference | Ungrounded elaboration, correctly self-flagged |
| 6 | Registry Run Key Persistence / T1547.001 | `...CurrentVersion\Run\Updater` | Yes — flagged "high-severity" framing, "move laterally or steal data" claim | Ungrounded elaboration, correctly self-flagged |
| 7 | Registry IFEO Debugger Hijack / T1546.012 | `...Image File Execution Options\sethc.exe\Debugger` | Host only | Clean — matches the retrieved MITRE technique text closely |
| 8 | Scheduled Task Creation via schtasks.exe / T1053.005 | `schtasks.exe /create /tn Updater ...` | Host only | Clean — recommendations trace directly to the playbook's investigation steps |
| 9 | Suspicious Scheduled Task via PowerShell Cmdlet / T1053.005 | `Register-ScheduledTask`/`New-ScheduledTaskAction` | Yes — flagged "high-severity ... matches known indicators," "common technique for stealthy abuse," signed-binary rationale | Ungrounded elaboration, correctly self-flagged |
| 10 | Suspicious Mshta Execution / T1218.005 | `mshta.exe http://185.220.101.5/payload.hta` | Yes — flagged "web-filtering" mischaracterization (source says application-control/browser security, not web-filtering), invented `.js`/`.vbs` file types, VLAN/EDR-rule specifics | Ungrounded elaboration + one real mischaracterization, correctly self-flagged |

## Issues found

**1. Self-critique conflates "not in the retrieved chunks" with "hallucination."** It flags the
incident's own `host` field on every single run, because `host` comes from the incident context
dict (`explain_service._incident_to_dict` / `format_incident_context`), not the retrieved KB
chunks — but it's real, first-party data, not a fabrication. This means the mere presence of a
`critique` note doesn't tell you anything on its own; a human still has to read what it actually
says. Not a bug in the traditional sense (the mechanism is doing what it's designed to do — compare
the draft against retrieved context), but worth knowing before treating "critique is non-null" as a
proxy for "found a problem" anywhere in the product (e.g. a future UI badge).

**2. One real hallucination slipped past self-critique (spot-check #2).** The execution-policy-bypass
incident's explanation claimed an `-enc`/`-EncodedCommand` flag that the crafted event never had.
Root cause: the knowledge base only has a playbook for the *encoded-command* T1059.001 scenario
(`T1059_001_powershell_execution.md`), not one specific to execution-policy-bypass, so retrieval's
best available match pulled in that playbook's specific technical detail, and the LLM presented it
as fact about this incident rather than general technique background. This is the one clear case
where self-critique should have caught something concrete and checkable (the crafted `CommandLine`
was right there in the incident context) and didn't.

**3. Hallucination density roughly tracks knowledge-base playbook coverage.** The KB has playbooks
for only 5 of the 10 rules' techniques (T1059.001, T1053.005, T1071.001, T1547.001, and — not
exercised here — T1003). For the 3 techniques with **no** playbook (T1105, T1546.012, T1218.005),
2 of 3 explanations (certutil/T1105, file-write/T1105, mshta/T1218.005 — 3 of 3 actually, since both
T1105 cases showed it) had noticeably more fabricated specifics in the "Recommended next steps"
section (invented Windows Event IDs, VLAN quarantine steps, specific file extensions, EDR rule
suggestions) than the 5 playbook-backed rules, whose recommendations traced closely to the
playbook's own Investigation/Containment/Remediation steps. IFEO (T1546.012) was a partial
exception — its MITRE technique doc alone is unusually detailed, which appears to have reduced (but
not eliminated) the need for the LLM to fill gaps. **Takeaway for whoever picks this up next:**
adding playbooks for T1105, T1546.012, and T1218.005 (3 more playbooks, bringing total KB coverage
to 8 of 10 rule techniques) would likely reduce hallucinated recommendation content more than any
prompt change.

## Summary

Self-critique (Day 8) does what the roadmap predicted — it **reduces but doesn't eliminate**
hallucination. Across 10 real spot-checks, it correctly self-flagged unsupported elaboration in 7
of 10 explanations (all 7 in the "Recommended next steps" section, i.e. invented specifics the KB
never provided), left 2 of 10 clean because the retrieved playbook/MITRE content already covered
everything stated, and missed one concrete, checkable hallucination (#2) where the wrong technical
detail was imported from an imperfectly-matched playbook rather than invented from nothing.
No explanation got a MITRE technique ID wrong, and every explanation's headline "What happened"
summary was directionally correct — the hallucinations found were all in supporting detail
(rationale, specific event IDs/tools, technique framing), not the core finding. The clearest,
lowest-effort improvement available is closing the KB's playbook gap (finding #3) rather than
touching the prompt or the self-critique mechanism itself.
