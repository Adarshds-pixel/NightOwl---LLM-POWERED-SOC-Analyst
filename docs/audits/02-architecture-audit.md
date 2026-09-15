# Architecture Audit: NightOwl

**Date:** September 2026  
**Document:** `docs/audits/02-architecture-audit.md`  
**Status:** Read-Only Audit Complete  

---

## 1. Executive Summary

NightOwl's architecture relies on a strictly layered backend (Routes → Services → Models) using FastAPI and SQLAlchemy, paired with a React 19 single-page application. The core pipeline processes EVTX telemetry, normalizes it, evaluates it against a custom Sigma-style engine, and generates incidents, which are then enriched via a RAG-based LLM system (Groq + ChromaDB).

Overall, the application achieves its stated goals as a zero-infrastructure SOC analyst copilot. However, several architectural decisions meant to avoid complex infrastructure (like message queues or Redis) have introduced severe scalability bottlenecks, data consistency flaws, and memory risks.

## 2. Component Analysis & Data Flow

### 2.1 Ingestion & Normalization
**Architecture:** Synchronous HTTP upload → Temp file spooling → Python-EVTX parsing → In-memory normalization & sorting.
- **Strengths:** Thread-pool offloading in FastAPI prevents blocking the main event loop.
- **Weaknesses (Scalability/Memory):** The application sorts the entire parsed EVTX payload in memory before persisting it. The `_timestamp_sort_key` normalizes every event during sort, and `ingest_records` normalizes them again. This $O(N \log N)$ duplicated processing creates severe memory and CPU bottlenecks for large (e.g., 100MB+) EVTX files.
- **Risks:** FastAPI's default `SpooledTemporaryFile` behavior accepts and writes the entire upload to disk before checking `MAX_UPLOAD_BYTES`, leading to trivial disk-exhaustion risks.

### 2.2 Persistence & Transactions
**Architecture:** SQLAlchemy ORM with a dependency-injected session generator (`get_db`).
- **Strengths:** Explicit database flushing prevents holding massive uncommitted state in memory.
- **Weaknesses (Data Consistency):** The ingestion transaction boundary is fatally flawed. `event_service.save_events` explicitly commits the transaction *before* detection rules are evaluated. If the detection engine crashes, the events are saved without any corresponding alerts. Re-uploading the file triggers deduplication, permanently skipping the events and resulting in irreversible false negatives.
- **Risks:** Unbounded database growth. `GET /events?q=...` uses leading-wildcard `ILIKE` queries against a continuously growing table without indexing or data retention policies, guaranteeing eventual query timeouts.

### 2.3 Detection & Correlation Engine
**Architecture:** In-memory synchronous rule evaluation during ingestion. Sequences are evaluated post-batch. Incidents are grouped by a 1-hour temporal window per host.
- **Strengths:** The sequence engine handles multi-event patterns reliably without needing a distributed stream processor like Kafka.
- **Weaknesses (Coupling/Performance):** The incident grouping logic (`find_or_create_incident`) runs a separate database `SELECT` for every individual rule match. For noisy files, this results in hundreds of N+1 queries.

### 2.4 AI & RAG Subsystem
**Architecture:** LangChain with Groq APIs. In-memory ChromaDB for vector retrieval. Background tasks for asynchronous AI opinions.
- **Strengths:** `LLMProviderError` cleanly abstracts provider failures. Background tasks prevent LLM latency from blocking the main HTTP ingestion response.
- **Weaknesses (Failure Recovery & State):** While background tasks update the DB to `failed` on error, there is no retry queue. Furthermore, `llm_client.py` and `cache.py` rely on unbounded in-memory dictionaries (`_explain_cache`, `_chat_cache`). Expired entries are only cleared on cache hits, leading to continuous memory growth.
- **Risks:** The `_explain_cache` is keyed solely by `incident_id`. If new alerts are added to an incident via the 1-hour grouping window, the cached LLM explanation remains stale and does not reflect the new evidence.

### 2.5 API & Frontend Contracts
**Architecture:** RESTful API with client-side polling.
- **Strengths:** Clear separation of concerns; the frontend remains purely presentational.
- **Weaknesses (Contract Mismatches):** The `/events` API lacks `event_id` filtering. The frontend implements this as a client-side filter over paginated server responses, resulting in empty table states while claiming thousands of results exist.
- **Risks:** Polling inefficiencies. The frontend `IncidentsDataProvider` fires 7 concurrent requests per cycle, which routinely triggers reverse-proxy rate limiters.

### 2.6 Deployment & Security Boundaries
**Architecture:** Monolithic containerization. In-memory token bucket rate limiting.
- **Strengths:** Simple deployment with minimal external dependencies.
- **Weaknesses (Single Points of Failure):** The in-memory rate limiter keys on `request.client.host`. Without `ProxyHeadersMiddleware`, a deployment behind a reverse proxy treats all users as a single IP, causing system-wide Denial of Service if any single user trips the rate limit.

## 3. Intentional Scope Decisions
The following are documented architectural choices meant to minimize deployment complexity and should **not** be treated as bugs:
1. **No External Message Broker (Kafka/RabbitMQ):** Asynchronous tasks rely on `fastapi.BackgroundTasks`.
2. **No Redis:** Caching and rate limiting are intentionally held in Python process memory.
3. **No WebSockets/SSE:** Real-time updates rely on client-side polling.
4. **Single-Admin Auth:** Complex RBAC is omitted by design.

## 4. Recommended Target Architecture
While adhering to the zero-infrastructure philosophy, the following architectural shifts are necessary for production reliability:
1. **Unified Transaction Boundaries:** Push all `db.commit()` calls up to the route handler or top-level service orchestrator to guarantee atomic ingestion.
2. **LRU Caching:** Replace unbounded Python `dict` caches with bounded `lru_cache` or custom eviction mechanisms.
3. **Proxy Awareness:** Introduce `ProxyHeadersMiddleware` to correctly parse `X-Forwarded-For` headers.
4. **Optimized Queries:** Collapse N+1 database queries into bulk `IN (...)` selects and introduce Postgres Full-Text Search (TSVector) for unbounded tables.
