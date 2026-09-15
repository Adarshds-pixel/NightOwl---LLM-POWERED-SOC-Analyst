# Repository Inventory & Initial Findings

**Date:** September 2026  
**Document:** `docs/audits/01-repository-inventory.md`  
**Status:** Complete

---

## 1. Executive Summary
This document provides a high-level inventory of the NightOwl repository structure, technology stack, and initial discovery findings. It serves as the foundational overview for subsequent, deeper architectural and security audits.

## 2. Technology Stack Inventory

### Backend
- **Framework:** FastAPI
- **Language:** Python 3.13
- **ORM / Database:** SQLAlchemy (SQLite/PostgreSQL)
- **Log Parsing:** Python-EVTX
- **Task Management:** FastAPI `BackgroundTasks` (No external message brokers)

### Frontend
- **Framework:** React 19
- **Build Tool:** Vite
- **Styling:** Tailwind CSS v4
- **State/Routing:** React Router, Context API

### AI & RAG Subsystem
- **Orchestration:** LangChain
- **LLM Provider:** Groq
- **Vector Database:** ChromaDB (Local `PersistentClient`)

---

## 3. Initial Discovery Findings
During the initial repository scan, several high-level architectural risks and implementation patterns were identified. These findings have been fed into the subsequent deep-dive audits (02 through 05):

1. **Proxy Rate Limiting Limitations:** 
   Rate limiting is keyed directly on `request.client.host` without `ProxyHeadersMiddleware`, which will cause IP collisions behind reverse proxies.
2. **In-Memory State Growth:** 
   Process-global dictionaries are used for rate limiting (`_buckets`) and AI caching (`_explain_cache`) without active eviction loops, risking long-term memory leaks.
3. **React 19 Strict Mode Violations:** 
   Observed patterns of ref access during render and cascading re-renders via synchronous `setState` in effects on the frontend.
4. **Large File Buffering Risks:** 
   FastAPI's `SpooledTemporaryFile` defaults expose the system to memory/disk buffering risks during large EVTX file ingestions.
5. **Database Query Degradation:** 
   Unbounded database growth combined with `ILIKE` wildcard searches (without appropriate TSVector indexing) presents a severe scalability risk.
6. **Configuration Secrets:** 
   The application falls back to empty strings for critical configuration items like the session secret if environment variables are not strictly provided.
7. **ChromaDB Concurrency:** 
   Non-isolated ChromaDB persistent storage presents concurrency issues if deployed in multi-worker environments (e.g., Uvicorn with multiple workers).
8. **Untrusted Data in Prompts:** 
   Initial scans reveal prompt injection risks where raw telemetry (e.g., command-line arguments) is interpolated directly into LLM prompts without sandboxing.

---
*Note: The findings outlined here have been expanded upon and prioritized in `docs/audits/MASTER_AUDIT.md`.*
