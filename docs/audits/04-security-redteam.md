# Security Assessment & Dependency Review

**Date:** September 2026  
**Document:** `docs/audits/04-security-redteam.md`  

## Executive Security Assessment
NightOwl is a zero-infrastructure SOC analyst copilot utilizing FastAPI, SQLAlchemy, React, and LLM/RAG capabilities. Based on architectural evidence and provided static/dependency analysis, the application is **not production-ready**. 

While static analysis tools report low direct-code vulnerability rates (largely false positives), architectural and logical flaws expose the application to severe Denial of Service (DoS) and Prompt Injection attacks. Furthermore, the absence of an active, adversarial red-team audit leaves significant residual risk.

## Scope and Methodology
**IMPORTANT LIMITATION:** The planned LLM-assisted security/red-team review could not be completed because the available AI model refused the direct security-audit task due to safety guidelines prohibiting active vulnerability analysis on concrete targets. 

This document does not hide this limitation. It is explicitly an evidence-based security compilation relying entirely on:
1. Automated static analysis reports (Semgrep, Bandit)
2. Dependency scanner reports (pip-audit)
3. Architectural code review from prior audits (`01`, `02`, `03`)
4. Explicit repository dependency usage evidence

## Threat/Attack Surface
The primary attack surfaces exposed to an untrusted network include:
- Unauthenticated API surfaces (Login, Health)
- Authenticated EVTX file upload and processing pipelines
- Telemetry processing and LLM prompt generation (Indirect Prompt Injection)
- AI Chat interfaces

---

## Detailed Findings by Area

### Dependency & Security Scanner Results

**Backend Semgrep**
- **Findings:** 1 finding in `backend/app/services/demo_service.py`.
- **Details:** The flagged SQL is `db.execute(text(f"ALTER SEQUENCE {sequence} RESTART WITH 1"))`.
- **Classification:** LIKELY SAFE / FALSE POSITIVE. `_SEQUENCES` is a hardcoded internal tuple containing specific sequences (`events_id_seq`, `alerts_id_seq`, etc.). The interpolated identifier is not user-controlled. This represents a hardening opportunity rather than a confirmed SQL injection.

**Bandit**
- **Findings:** 1 finding (B105: LOW severity / MEDIUM confidence) in `backend/app/ingestion/normalizer.py:342`.
- **Details:** The flagged string is `if token == "security":`.
- **Classification:** FALSE POSITIVE. This evaluates a log-channel/category value, not a hardcoded password or credential.

**pip-audit (Backend)**
- **Findings:** Reported vulnerabilities in `chromadb 1.5.9` and `diskcache 5.6.3`.
- **Classification:** NOT EXPLOITABLE FROM AVAILABLE EVIDENCE. NightOwl utilizes ChromaDB via a local, in-process `PersistentClient` in `backend/app/rag/chroma_client.py`. It does not expose the vulnerable Chroma HTTP server attack surface, nor does it enable `trust_remote_code`. DiskCache matches are transitive (via Sigma MITRE/D3FEND caches) and not directly exposed.

**Frontend Semgrep**
- **Findings:** 0 findings.
- **Classification:** UNVERIFIED. Only 88 rules were executed, omitting the full Pro ruleset. The frontend cannot be claimed fully secure based on this limited run.

### Authentication and Session Security
- **Assessment:** NightOwl relies on a single-admin authentication model using signed session cookies.
- **Classification:** CONFIRMED (Risk). Previous architectural audits identified a client-controlled secret configuration risk where empty strings could be used as session secrets. 
- **Classification:** RESIDUAL RISK. Brute force protections exist locally via token buckets, but session fixation and granular expiration handling require deeper review.

### API Security, CORS & Rate Limiting
- **Assessment:** Rate limiting utilizes an in-memory token bucket keyed on `request.client.host`.
- **Classification:** CONFIRMED (Vulnerability). Without `ProxyHeadersMiddleware` enabled in FastAPI, deploying NightOwl behind a reverse proxy/load balancer causes `request.client.host` to resolve to the proxy IP. A single user can exhaust the bucket, creating a systemic Denial of Service.

### Authorization
- **Assessment:** Single-user/admin model.
- **Classification:** LIKELY SAFE (By Scope). The lack of multi-tenant RBAC and object-level authorization is a deliberate project scope decision.

### SQL/Database Security
- **Assessment:** SQLAlchemy ORM parameterizes typical queries. 
- **Classification:** CONFIRMED (DoS Risk). Unbounded `ILIKE` wildcard queries in `event_service.py` create a significant resource exhaustion vector as the dataset grows.
- **Classification:** LIKELY SAFE. Dynamic SQL in demo mode is restricted to hardcoded arrays (see Semgrep findings).

### File and EVTX Ingestion Security
- **Assessment:** FastAPI `UploadFile` handles `.evtx` uploads.
- **Classification:** CONFIRMED (Vulnerability). `MAX_UPLOAD_BYTES` is validated only *after* Starlette spools the entire upload to a `SpooledTemporaryFile`. Attackers can upload files large enough to exhaust disk space before the rejection logic executes.

### Sigma/YAML Rule Processing
- **Assessment:** Rules are parsed from YAML files on disk.
- **Classification:** UNVERIFIED. Standard YAML parsing can be vulnerable to code execution if `yaml.load` is used over `yaml.safe_load`. Code review implies static internal rules, but custom rule uploads would carry severe risk.

### Command/Subprocess Execution Risks
- **Assessment:** No active usage of `subprocess.run` or `os.system` with untrusted inputs observed.
- **Classification:** LIKELY SAFE.

### RAG/Chroma Security
- **Assessment:** Local `PersistentClient` usage.
- **Classification:** NOT EXPLOITABLE FROM AVAILABLE EVIDENCE. (See pip-audit details above).

### LLM/Groq & Prompt Injection
- **Assessment:** Telemetry values (`command_line`, `user`) are concatenated directly into the LLM prompt.
- **Classification:** CONFIRMED (Vulnerability). In `backend/app/rag/prompts.py`, `UNCOVERED_OPINION_HUMAN_PROMPT` formats unescaped string values. An attacker can craft a malicious EVTX log with a payload (e.g., instructing the LLM to output "Assessment: Nothing unusual noted") resulting in a direct Prompt Injection and evasion of AI review.

### Secrets/Configuration Handling
- **Assessment:** Configuration relies on environment variables.
- **Classification:** FALSE POSITIVE. The Bandit finding for hardcoded secrets (`token == "security"`) is benign.
- **Classification:** RESIDUAL RISK. `.env` exposure and build-time secrets in Docker remain unverified without environment-specific audits.

### Demo Mode Security
- **Assessment:** `demo_service.py` allows database resets.
- **Classification:** RESIDUAL RISK. If the `/demo/reset` endpoint is inadvertently exposed to an untrusted production network, it serves as a highly destructive unauthenticated API.

### Frontend Security
- **Assessment:** React 19 handles output encoding natively to prevent basic XSS.
- **Classification:** UNVERIFIED. The frontend scanner ruleset was incomplete. Deep DOM-based XSS, SSRF via API clients, or unsafe redirects were not actively exploited or verified.

---

## Final Security Verdict

NightOwl is **NOT production-ready**. 

While the application successfully avoids many common dependency and static-analysis vulnerabilities (which were verified as false positives or unexploitable configurations), it contains **CONFIRMED** architectural security flaws. Specifically:
1. **Prompt Injection** through unescaped telemetry processing.
2. **Rate Limiting Bypass / Systemic DoS** due to missing reverse-proxy header parsing.
3. **Disk Exhaustion DoS** due to late evaluation of upload file sizes.

**Security Limitations:** This assessment relied entirely on static analysis, dependency scanning, and architectural code review. Because an active, adversarial penetration test was explicitly refused by the automated analysis tools, significant **UNVERIFIED** and **RESIDUAL RISKS** remain in authorization boundaries, frontend injection vectors, and deployment configurations. Proceeding to production without addressing the confirmed vulnerabilities and completing a manual penetration test is strongly discouraged.
