# NightOwl — Decision Log

One entry per significant decision, per Volume 3 §8.6.

---

**2026-08-16 — Chose Google Gemini free tier (via `langchain-google-genai`) as the LLM provider for Day 7's prompt + LLM wiring.**
- **Alternatives considered:** Groq (free tier, fast Llama/Mixtral inference); paid APIs (OpenAI, Anthropic) — ruled out immediately, project policy is free-tier only.
- **Why this one:** Gemini's free tier (Google AI Studio) needs no billing setup and has workable Flash-tier daily quotas; `langchain-google-genai` plugs directly into the `ChatPromptTemplate`/message types already used in `rag/prompts.py`, so `rag/llm_client.py` needs no bespoke request/response glue.
- **Model:** `gemini-flash-latest` — Google's alias that always points at their current recommended free-tier Flash model, rather than a pinned dated snapshot (e.g. `gemini-2.5-flash`, scheduled for retirement 2026-10-16). Avoids a forced mid-roadmap follow-up commit when Google rotates models. Overridable via `LLM_MODEL` in `.env`.
- **Reversible?** Yes — the LLM call is fully abstracted behind `rag/llm_client.py`'s `get_llm_client()`/`generate()`; swapping providers touches this one file, not any caller.

---

**2026-08-16 — pySigma used for rule validation only; NightOwl's own engine does per-event evaluation (Day 7 detection engine v1).**
- **What we evaluated:** whether `pysigma` (the official Sigma rule library) could handle both parsing *and* evaluating rules against a live event, end to end.
- **What we found:** pySigma's design centers on *backends* — converters that turn a parsed rule into a target query language (Elasticsearch DSL, Splunk SPL, etc.) to run against an external log store. There's no official backend for evaluating a rule against a single in-memory Python object, which is exactly what `POST /ingest` needs (one normalized event, evaluated in-process, no external SIEM in this stack).
- **Decision:** use `pysigma`'s `SigmaRule.from_yaml()` at load time for real structural validation (catches malformed rules with proper error messages — a genuine, non-decorative use of the library), then evaluate with a small hand-rolled interpreter (`app/detection/engine.py`) over the rule's `detection` block, loaded separately via `yaml.safe_load`. The evaluator supports the common subset of Sigma semantics: named selections (AND across fields, OR across a value list), `contains`/`startswith`/`endswith` field modifiers, and a boolean `condition` string (`and`/`or`/`not`/parentheses) via a small recursive-descent parser — not `eval()`, since rule files are treated as untrusted input.
- **Known v1 limitations (by design, not oversight):** no `|re` or glob-wildcard modifiers, no `1 of`/`all of` condition shorthand, no named multi-condition rules. Easy to extend later if a specific rule needs it.
- **Reversible?** Yes — `rule_loader.py`/`engine.py` are the only files that know about this; a future move to a full pySigma backend (e.g. if the project adds a real SIEM/Elasticsearch target) wouldn't change any caller.

**2026-08-16 — Detection rules match against real Sysmon field names (Image, CommandLine, DestinationIp, ...), not NightOwl's normalized event schema.**
- **Alternatives considered:** writing rules against the normalized schema's own field names (`process`, `command_line`, ...) to keep the detection engine fully decoupled from Sysmon's raw XML shape.
- **Why real Sysmon names instead:** rules become portable from public Sigma/SigmaHQ sources — a stronger, more credible claim for the project than an invented vocabulary, and immediately recognizable to anyone familiar with real SOC tooling.
- **How the coupling risk was avoided:** `normalizer.py` already computes a flattened `{FieldName: value}` dict from each record's `EventData` before mapping the 3 fields it promotes to columns. `NormalizedEvent` now also carries that full dict as `event_data` (`schemas/event.py`), so `engine.py` gets every Sysmon field for free — not just the 3 the normalizer promotes — without re-parsing XML itself. The engine matches against the union of `event_data` and the normalized fields, so both vocabularies work.
- **Reversible?** Yes — `event_data` is additive; nothing that read `NormalizedEvent` before Day 7 is affected.

---

**2026-08-18 — `Alert.severity` is a direct pass-through of the matched rule's `level` string (Day 8 alert persistence).**
- **Alternatives considered:** a fixed severity enum (`low`/`medium`/`high`/`critical`) with an explicit `level -> severity` translation table, in case rule authors ever use non-standard level strings.
- **Why pass-through instead:** `Alert.severity` is a plain `String(50)` with no DB-level constraint, and every rule file's `level` already comes from Sigma's own small standard vocabulary (`informational`/`low`/`medium`/`high`/`critical`). A translation table would just map each string to itself — added indirection with no behavior difference.
- **Decision:** `services/detection_service.py`'s `create_alert` sets `severity = match.level` directly.
- **Reversible?** Yes — confined to one line in `create_alert`; if a real enum constraint is added to the `alerts` table later, only this function needs to change.
- **Update (2026-08-19, Day 10):** `match.level` is no longer the raw, unweighted Sigma rule level — `engine.evaluate_event` now runs it through `severity_service.compute_severity()` before building the `RuleMatch` (see the Day 10 entry below), so this pass-through decision still holds, but what's being passed through changed meaning.

---

**2026-08-19 — Registry-based detection scoped to Sysmon Event ID 13 (Value Set) only (Day 9, 10 rules total).**
- **What we needed:** rules for registry-based persistence (T1547.001 Run keys, T1546.012 IFEO debugger hijack), per the roadmap's "cover registry... categories" goal.
- **Alternatives considered:** a `registry_event` category spanning all of Sysmon's registry event IDs (12 "Object create/delete", 13 "Value Set", 14 "Value Rename"), matching Sigma's own broader `registry_event` category semantics.
- **Why ID 13 only:** the engine's `CATEGORY_TO_EVENT_ID` maps one category to exactly one event ID (a v1 design constraint from Day 7, not changed here). Value-Set is the event that actually carries the interesting data (`TargetObject`, `Details`) for both target rules — a Run key being *set* to point at malware, or a Debugger value being *set*. Object create/delete and value-rename would need either a second category name or a multi-event-ID mapping, both bigger changes than this scope needs.
- **No `normalizer.py` change needed:** `NormalizedEvent.event_data` already carries every raw `EventData` field regardless of event ID (confirmed working since Day 5's "unrecognized event IDs still normalize" test coverage), so registry rules match `TargetObject`/`Details` out of `event_data` exactly like existing rules match `Image`/`CommandLine`.
- **Reversible?** Yes — extending to IDs 12/14 later is additive (either a new category name, or evolving `CATEGORY_TO_EVENT_ID` to a category -> set-of-event-IDs mapping); no existing rule or test depends on ID 13 being the only registry event supported.

---

**2026-08-19 — "Scheduled task" rules (T1053.005) are `process_creation` rules, not a dedicated scheduled-task logsource (Day 9).**
- **Why:** Sigma's scheduled-task-management category isn't backed by a Sysmon event the way this project's other categories are (it's typically Security-log Event ID 4698, which this project doesn't ingest). Detecting `schtasks.exe /create` and PowerShell's `Register-ScheduledTask`/`New-ScheduledTaskAction` cmdlets as `process_creation` events (Sysmon Event ID 1, already fully supported) is both the standard real-world detection approach and needs zero engine changes.
- **Reversible?** Yes — if Security-log ingestion is ever added, a dedicated category could be introduced without touching these two rules' logic, just their `logsource.category`.

---

**2026-08-19 — Severity scoring combines base Sigma level + MITRE tactic weight, both derived from each rule's own `tags:` list (Day 10).**
- **What we needed:** "combine rule severity + technique tactic weight" per the roadmap, so e.g. a "medium" rule tagged `command_and_control` ranks above a "medium" rule tagged only `reconnaissance`.
- **Where the tactic comes from:** rule authors already tag rules with both a technique id (`attack.t1547.001`) and tactic name(s) (`attack.persistence`) — Day 9's `rule_loader.py` change parses both out of the plain `tags:` list (not from pySigma's parsed object model, consistent with how `condition`/`detections` are already parsed from the raw YAML dict). This is tag *extraction*, not MITRE-dataset validation — validating tag values against the real ATT&CK dataset stays Day 11's job (`mitre/validator.py`).
- **Formula:** `services/severity_service.py`'s `compute_severity(base_level, tactics)` — base rank 1-5 (informational..critical) plus the *highest* weight among the rule's tactics (0 for recon/resource-dev, +1 for initial-access/execution/persistence/priv-esc/defense-evasion, +2 for credential-access/discovery/lateral-movement/collection, +3 for command-and-control/exfiltration/impact), capped at critical. Tactic *tag spelling* matches this project's existing convention (underscores, e.g. `command_and_control`, not MITRE's site hyphens) since that's what the Day 7/8 seed rules already use.
- **Where it's applied:** `engine.evaluate_event` calls this when building each `RuleMatch`, so `RuleMatch.level` (and therefore `Alert.severity`) is always the final weighted value, not the raw rule level. Confirmed live: the Day 7 seed rule (`level: high`, tagged `attack.execution`) now produces `severity: critical` alerts (high=4 + execution weight 1 = 5), a visible, intentional behavior change from Day 8.
- **Reversible?** Yes — the weight table and formula are isolated in one function; existing tests/rules with no tactics see zero behavior change (weight 0), which is why no Day 7/8 test needed updating for this.

---

**2026-08-19 — `backend/tests/` reorganized to mirror `backend/app/`'s package structure; `test_detection.py` moved despite being the one roadmap-mandated exact filename.**
- **Why:** user raised a (correctly investigated and disproven) concern that core logic might live in `tests/` instead of `app/`; the real, separate issue was that all 24 test files sat flat in `backend/tests/`, named `test_dayN_<module>.py` after the roadmap's day cadence rather than `app/`'s actual package layout — unusual/internal-looking to anyone unfamiliar with the roadmap (e.g. a presentation judge). Confirmed via full audit: Vol3's standards doc does not mandate `test_dayN_*` naming; it emerged ad hoc, day by day.
- **What changed:** new subpackages `tests/{api,detection,services,ingestion,mitre,rag}/` mirroring `app/`'s own subpackages 1:1; all `dayN` prefixes dropped; a new `tests/conftest.py` `api_client` fixture replaces near-identical `TestClient`+in-memory-SQLite-+-`get_db`-override boilerplate that was duplicated across 4 ingest-route test files; `test_day7_rule_loader.py` merged with `test_day9_detection_rules.py` into `detection/test_rule_loader.py` (both are rule_loader.py concerns); `test_day3_backend_setup.py` merged with `test_day3_models.py` into `test_health_and_models.py`; `test_day8_detection_rules.py` deleted after confirming (by comparing exact matching/benign `event_data` fixtures, not assumed) its coverage was a strict subset of `detection/test_rules_matrix.py`'s full 10-rule fire/no-fire matrix. Net: 24 test files → 21 + `conftest.py`, zero coverage lost (155 → 145 tests, the 10-test difference being exactly the confirmed-redundant deleted file).
- **Deliberate deviation:** Day 10's roadmap row explicitly names `backend/tests/test_detection.py` verbatim as a Files-column deliverable. Renaming it to `detection/test_rules_matrix.py` breaks that exact-filename match — a conscious tradeoff for structural consistency once the user prioritized clean organization over literal roadmap-filename fidelity for this one file.
- **Verification discipline:** full suite re-run after every individual move/merge/delete step (not just once at the end), so any regression would be caught against the specific change that caused it. Final count (`145 passed`) matched the predicted `155 − 10` exactly.
- **Reversible?** Yes — this is a pure file/import-path reorg; no `app/` logic changed. `git mv` was used for straight renames so history is preserved via `git log --follow`; the 3 merge/delete operations lose direct `git mv` tracking for those specific old paths but the content itself is fully preserved in the new files.

---

**2026-08-18 — Unknown/deprecated/revoked MITRE technique tags are warn-only, not rule-rejecting (Day 11).**
- **What we needed:** `mitre/validator.py` (Pair 2's Day 6 scaffold) deliberately left the acceptance policy for invalid technique ids to Pair 1 — its docstring says so explicitly, since the scaffold itself already keeps deprecated/revoked techniques in the lookup rather than dropping them.
- **Alternatives considered:** reject/skip a rule outright (like a structurally malformed rule file) if its `technique_id` doesn't validate.
- **Why warn-only instead:** a bad MITRE tag is a metadata problem, not a detection-logic problem — the rule's `detection`/`condition` still work correctly and should keep firing regardless of whether its tag typo'd `T1547.oo1` or references a since-revoked id. Treating it the same as a missing `detection` block (Day 7's `RuleLoadError`, rule dropped entirely) would silently lose real detection coverage over a documentation issue. This also matches `severity_service.compute_severity`'s existing "unrecognized tactic contributes 0 weight, doesn't raise" fallback philosophy — untrusted/imperfect tag data degrades gracefully rather than breaking things.
- **Where:** `app/detection/rule_loader.py`'s new `_validate_technique()`, called from `_load_one()` right after `_parse_tags()`; logs one `logger.warning` per rule with an unknown/deprecated/revoked technique id (distinct messages per case), same log-and-continue shape as the existing malformed-rule-file handling.
- **Incident-level rollup already done:** the roadmap's other Day 11 ask — "roll up technique IDs from an incident's alerts" — was already satisfied by Day 9's `services/incident_service.py` (`find_or_create_incident` merges each match's `technique_id` into `Incident.mitre_technique_ids`); no additional Day 11 change was needed there.
- **Not done as part of Day 11 (deliberately deferred, not an oversight):** `models/rule.py`'s `mitre_technique_id` column still has nothing writing to it — no `Rule` row is ever persisted anywhere in the codebase today. The Day 11 roadmap row's own Files column only lists `detection/rules/*.yml`, `mitre/validator.py`, `services/incident_service.py` (not `models/rule.py`), and no roadmap day currently reads from the `rules` table either — the closest consumer is Pair 2's Day 16 rules-manager UI (`api/routes_rules.py`, enable/disable), which is a future day for the other pair. Persisting `Rule` rows now would be building ahead of an actual consumer; left as a gap for whichever day adds `routes_rules.py`.
- **Reversible?** Yes — `_validate_technique()` only logs; it doesn't change `LoadedRule`'s shape or any caller's behavior. Switching to a rejecting policy later is a one-function change.
