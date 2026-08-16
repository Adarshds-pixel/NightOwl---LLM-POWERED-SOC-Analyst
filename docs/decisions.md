# NightOwl — Decision Log

One entry per significant decision, per Volume 3 §8.6.

---

**2026-08-16 — Chose Google Gemini free tier (via `langchain-google-genai`) as the LLM provider for Day 7's prompt + LLM wiring.**
- **Alternatives considered:** Groq (free tier, fast Llama/Mixtral inference); paid APIs (OpenAI, Anthropic) — ruled out immediately, project policy is free-tier only.
- **Why this one:** Gemini's free tier (Google AI Studio) needs no billing setup and has workable Flash-tier daily quotas; `langchain-google-genai` plugs directly into the `ChatPromptTemplate`/message types already used in `rag/prompts.py`, so `rag/llm_client.py` needs no bespoke request/response glue.
- **Model:** `gemini-flash-latest` — Google's alias that always points at their current recommended free-tier Flash model, rather than a pinned dated snapshot (e.g. `gemini-2.5-flash`, scheduled for retirement 2026-10-16). Avoids a forced mid-roadmap follow-up commit when Google rotates models. Overridable via `LLM_MODEL` in `.env`.
- **Reversible?** Yes — the LLM call is fully abstracted behind `rag/llm_client.py`'s `get_llm_client()`/`generate()`; swapping providers touches this one file, not any caller.
