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
