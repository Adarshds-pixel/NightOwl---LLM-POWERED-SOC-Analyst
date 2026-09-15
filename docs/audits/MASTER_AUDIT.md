# MASTER CROSS-SYSTEM AUDIT: NightOwl

**Date:** September 2026  
**Document:** `docs/audits/MASTER_AUDIT.md`  
**Sources:** `01-repository-inventory.md`, `02-architecture-audit.md`, `03-code-api-db-audit.md`, `04-security-redteam.md`, `05-frontend-audit.md`

---

## 1. Executive Summary
This document serves as the authoritative, cross-system synthesis of all NightOwl audits. It consolidates architectural reviews, code-level vulnerability analyses, frontend UX/UI inspections, and defensive security assessments into a single source of truth. 

NightOwl is designed as a zero-infrastructure SOC analyst copilot. While it successfully implements its core EVTX ingestion and LLM RAG pipelines without requiring complex external dependencies (e.g., Redis, Kafka), this simplicity has introduced critical transaction flaws, resource exhaustion vectors, and prompt injection attack surfaces.

## 2. Overall Risk Assessment
**STATUS: NOT PRODUCTION-READY**

NightOwl cannot be safely exposed to an untrusted network in its current state. The application suffers from a critical data loss (false negative) scenario during ingestion, as well as multiple High-severity (P1) vectors including reverse-proxy rate limiting key collapse, unconstrained file spooling, and LLM prompt injection attack surfaces that require mitigation.

## 3. Findings by Severity

| Severity | Count | Primary Impact Areas |
|----------|-------|----------------------|
| **CRITICAL (P0)** | 1 | Data Loss (Ingestion Transaction Integrity) |
| **HIGH (P1)** | 6 | Rate-Limit Collapse, Prompt Injection, File System DoS, CPU/Memory Spikes, UX Failure (Sorting, State Loss) |
| **MEDIUM (P2)** | 4 | API Degradation, Unbounded Memory/DB Growth, Frontend State Desync |
| **LOW (P3)** | 2 | Stale Caches, Print Styling |

## 4. Cross-Audit Contradictions & Intentional Exclusions

### Resolved Contradictions
- **Static Rules vs. UI Toggles:** The frontend audit (`05`) flagged disabled rule toggles as a UX frustration. The architecture audit (`02`) confirms rules are static YAML files. **Resolution:** The UI should be updated to display "Static" badges instead of disabled toggles.
- **Scanner Warnings vs. Actual Risk:** Static scanners flagged `ALTER SEQUENCE` SQL and `token == "security"` as vulnerabilities. **Resolution:** Audit `04` overrides these as FALSE POSITIVES based on internal system mechanics.

### Intentional Project Scope Exclusions (NOT Defects)
The following are deliberate zero-infrastructure design choices and should not be treated as bugs:
- **No Redis:** Reliance on in-memory Python dictionaries.
- **No Kafka/RabbitMQ:** Reliance on FastAPI `BackgroundTasks`.
- **No WebSockets:** Reliance on frontend interval polling.
- **Single-Admin Auth:** Lack of complex, multi-tenant Role-Based Access Control (RBAC).

---

## 5. Security Findings (Authoritative per 04-security-redteam)

- **[CONFIRMED - P1] LLM Telemetry Prompt-Injection Attack Surface:** Untrusted EVTX log fields (`command_line`, `user`) reach the model context unescaped via `UNCOVERED_OPINION_HUMAN_PROMPT`. Successful instruction-following or downstream security impact requires adversarial validation, but the attack surface is confirmed.
- **[CONFIRMED - P1] Reverse-Proxy Rate-Limit Key Collapse:** In-memory rate limiting keys on `request.client.host`. Without `ProxyHeadersMiddleware`, a load balancer causes all users to share one rate limit. Production exploitability depends on deployment topology.
- **[CONFIRMED - P1] Multipart Upload Limit Enforced After Parsing:** `MAX_UPLOAD_BYTES` is validated only *after* Starlette spools the entire upload. Production disk-exhaustion impact depends on upstream request-size controls (e.g., Nginx client_max_body_size).
- **[RESIDUAL RISK] Demo Mode API:** `/demo/reset` executes destructive database truncations. Highly dangerous if inadvertently exposed to production.
- **[RESIDUAL RISK] Session Cookie Security:** The single-admin session lacks granular expiration controls, and configuration may allow empty strings for the signing secret.
- **[FALSE POSITIVE] SQL Injection in Demo Service:** Semgrep flagged `ALTER SEQUENCE`. The interpolated sequence names are from a hardcoded internal tuple, not user input.
- **[FALSE POSITIVE] Hardcoded Secret:** Bandit flagged `token == "security"`. This is a log-channel category evaluation, not a credential.

## 6. Architecture, Code, API, and Database Findings

- **[P0] Ingestion Transaction Integrity:** Confirmed architectural defect. `db.commit()` is called *before* detection rules evaluate. If detection crashes, events are saved without alerts. Because retry/deduplication prevents detection from being rerun on those events, this leads to permanent alert loss.
- **[P1] $O(N \log N)$ Normalization Spikes:** EVTX chronological sorting evaluates `normalize_event` on every comparison, and then `ingest_records` normalizes again. Severe CPU bottleneck.
- **[P2] Unbounded Database ILIKE Queries:** Searches use `%pattern%` on multiple columns without TSVector indexing or retention policies. Guarantees eventual query timeouts.
- **[P2] Infinite Memory Dictionaries:** `_explain_cache` and rate limiter `_buckets` have no eviction loops, causing process memory to grow infinitely until OOM.
- **[P2] N+1 Query in Incident Details:** Fetching incident alerts executes a new `get_related_events` SQL query per alert.
- **[P3] Stale LLM Explanations:** `_explain_cache` is keyed solely by `incident_id`, serving stale summaries even if the grouping window appends new alerts to the incident.

## 7. Frontend Findings

- **[P1] Broken Global Table Sorting:** `IncidentsPage` slices its array for pagination *before* passing it to the sorting component, meaning analysts only sort the current 25 visible rows, burying critical threats on subsequent pages.
- **[P1] Permanent Prompt Loss on Error:** If the AI Assistant encounters a network failure or 429 rate limit, the analyst's complex query is erased without a retry option.
- **[P2] Client-Side Sysmon Filtering Mismatch:** The API lacks `event_id` filtering. The UI filters a paginated 25-item chunk, producing empty screens while claiming thousands of results exist.
- **[P2] Pagination Offset Stranding:** Changing page size (e.g., from 10 to 50) fails to reset the page index, stranding users on out-of-bounds offsets with empty tables.
- **[A11Y] Accessibility Failures:** Missing focus traps on modals, color-only severity indicators, non-keyboard-navigable MITRE cells, and contrast ratio failures on micro-typography.
- **[P3] Print / PDF Styling:** Dark mode background tokens persist in `@media print`, rendering exported dossier text illegible.

## 8. Dependency & Scanner Findings

- **Semgrep (Backend):** 1 finding (SQL). Reconciled as FALSE POSITIVE.
- **Bandit (Backend):** 1 finding (B105). Reconciled as FALSE POSITIVE.
- **pip-audit (Backend):** Vulnerabilities in `chromadb 1.5.9` and `diskcache 5.6.3`. **Reconciliation:** NOT EXPLOITABLE FROM AVAILABLE EVIDENCE. NightOwl uses ChromaDB via an in-process local `PersistentClient`, not the vulnerable HTTP server. Diskcache is a transitive dependency of Sigma.
- **Semgrep (Frontend):** 0 findings. **Reconciliation:** UNVERIFIED. Scan only evaluated 88 standard rules; deep DOM XSS or prototype pollution remain unverified.

## 9. Production-Readiness Blockers

NightOwl **must not** be deployed until the following are resolved:
1. **[P0] Data Loss Flaw:** The transaction boundary in `ingest_service.py` must be unified so events and alerts commit atomically.
2. **[P1] Reverse Proxy DoS:** `ProxyHeadersMiddleware` must be implemented (or upstream proxy controls verified) to prevent IP spoofing and global rate-limit throttling.
3. **[P1] Prompt Injection:** EVTX telemetry must be sandboxed or strictly typed as JSON to prevent malicious log strings from hijacking the LLM.
4. **[P1] Disk Exhaustion DoS:** A streaming `Content-Length` cutoff must be enforced *before* file spooling completes (or upstream Nginx limits explicitly documented/verified).

## 10. Recommended Remediation Priorities

**Phase 1: Production Blockers (P0 & P1)**
1. **[P0]** Move `db.commit()` in ingestion to guarantee atomic event+alert saves.
2. **[P1]** Enable `ProxyHeadersMiddleware` for FastAPI.
3. **[P1]** Sandbox LLM Prompt telemetry inputs against injection.
4. **[P1]** Add streaming upload size limits to prevent Disk DoS.

**Phase 2: High-Impact UX & Performance (P1)**
5. **[P1]** Fix global table sorting in `IncidentsPage`.
6. **[P1]** Implement `(normalized, raw)` tuple generation to remove dual-normalization overhead during ingestion sorting.
7. **[P1]** Preserve failed AI chat prompts in the UI state for retries.

**Phase 3: Long-Term Reliability (P2)**
8. **[P2]** Add bounded LRU caching or eviction to `_buckets` and `_explain_cache`.
9. **[P2]** Add native `event_id` filtering to the `/events` backend API.
10. **[P2]** Implement Postgres Full-Text Search (TSVector) to replace unbounded `ILIKE` wildcard queries.

**Phase 4: Polish & A11Y (P3)**
11. **[P3]** Update print CSS for executive dossiers.
12. **[P3]** Fix accessibility focus traps and contrast ratios.

## 11. Explicit Limitations and Unverified Areas
- **No Active Red-Teaming:** Automated LLM-assisted penetration testing was strictly prohibited. The security assessment relies heavily on static architecture review and dependency analysis.
- **YAML Deserialization:** The safety of parsing potentially untrusted Sigma YAML definitions was not dynamically fuzzed.
- **Frontend Injection:** Frontend XSS/SSRF via deeply nested React components was not dynamically verified due to the limited Semgrep ruleset.
- **Production Environment:** Docker, Nginx, and specific cloud hosting configurations remain unverified and assume secure external configurations.
