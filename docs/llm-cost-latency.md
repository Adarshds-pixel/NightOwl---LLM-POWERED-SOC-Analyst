# Day 12 (Pair 2): Token Usage & Response Time per Explanation

Roadmap task (`docs/02_NightOwl_Handbook_Vol2_Roadmap.md`, Phase 2 / Day 12): "measure
token usage and response time per explanation, document."

## Methodology

`backend/scripts/llm_cost_latency_check.py` runs `rag/explain_service.generate_explanation`'s
real two-call shape (retrieve → draft → self-critique) against 5 crafted incidents, using
`rag/llm_client.generate_with_metrics()` instead of the hot-path `generate()` so each call's
token usage and wall-clock latency are captured. It doesn't need Postgres/Docker — it builds
incident dicts directly and retrieves against the real, already-built Chroma knowledge base
(`data/chroma/`, from Day 4's `scripts/build_kb.py`).

The 5 incidents are a deliberate mix of techniques with knowledge-base playbook coverage
(T1059.001, T1053.005) and without (T1105, T1546.012, T1218.005), per
`docs/research/hallucination-eval.md`'s finding #3 (hallucination density roughly tracks
playbook coverage) — so this run also shows whether that KB gap shows up in retrieval/token
numbers, not just hallucination rate.

**Provider used: Groq** (`openai/gpt-oss-120b`), not the project's default Gemini — same reason
as the Day 10 hallucination spot-check: Gemini's free tier caps at 20 requests/day, and this
run alone needs 10 (5 incidents × 2 calls). At the time of this run, Gemini's daily quota was
already exhausted from other manual testing earlier the same day, which is itself a useful data
point (see "What this means for the free tier" below).

Reproduce with (no Postgres/Docker required, just a real key):
```
cd backend
# .env: LLM_PROVIDER=groq, GROQ_API_KEY=<your key>
./venv/Scripts/python.exe scripts/llm_cost_latency_check.py
```
Full per-call data is saved at `backend/scripts/llm_cost_latency_output.json`.

## Results (2026-08-19, Groq `openai/gpt-oss-120b`)

| # | Technique | Playbook in KB? | Chunks retrieved | Draft tokens (in/out/total) | Draft latency (s) | Critique tokens (in/out/total) | Critique latency (s) | Explanation total (tokens / s) |
|---|---|---|---|---|---|---|---|---|
| 1 | T1059.001 (encoded PowerShell) | Yes | 5 | 1803 / 719 / 2522 | 2.72 | 2118 / 790 / 2908 | 2.30 | 5430 / 5.02 |
| 2 | T1105 (certutil download) | No | 4 | 1462 / 609 / 2071 | 1.84 | 1769 / 1207 / 2976 | 12.56 | 5047 / 14.41 |
| 3 | T1546.012 (IFEO debugger hijack) | No | 5 | 1641 / 657 / 2298 | 20.16 | 1997 / 676 / 2673 | 24.02 | 4971 / 44.17 |
| 4 | T1053.005 (scheduled task) | Yes | 5 | 1562 / 495 / 2057 | 16.09 | 1797 / 883 / 2680 | 17.78 | 4737 / 33.88 |
| 5 | T1218.005 (mshta execution) | No | 2 | 1018 / 567 / 1585 | 9.91 | 1303 / 1122 / 2425 | 18.28 | 4010 / 28.19 |

**Averages across 5 explanations** (from `scripts/llm_cost_latency_output.json`'s `summary`):
- Draft: 1497 input / 609 output tokens, 10.14s latency
- Self-critique: 1797 input / 936 output tokens, 14.99s latency
- **Per explanation: ~4839 total tokens, ~25.13s wall-clock (draft + critique combined)**
- 24,195 tokens across all 10 calls in this run

## Observations

- **Self-critique roughly doubles both cost and latency per explanation.** Each `/explain` call
  makes 2 LLM calls (Day 8's design), and the critique call is consistently *more* expensive than
  the draft it's checking (higher input tokens, since it also carries the draft + sources; often
  higher output tokens too, e.g. #2 and #5 where critique output token count exceeds the draft's).
  This is the direct cost of the self-critique reasoning chain highlighted in the README as a
  standout feature — worth knowing precisely, since it's the single biggest lever on both latency
  and free-tier request/token budget.
- **Latency varies a lot between runs (1.8s–24s per call) and isn't obviously explained by token
  count alone** — #1's critique (2908 tokens) took 2.3s, while #3's draft (2298 tokens, *fewer*
  tokens than #1's critique) took 20.2s. This looks like Groq-side queueing/variance rather than
  anything in our code (`llm_client.py` makes one `.invoke()` call per attempt with no
  client-side throttling), consistent with a free-tier shared-capacity API. Practical
  implication: a fixed timeout budget for a demo should assume the slow end of this range, not
  the average — see the Day 12 `llm_timeout_seconds` default of 30s, comfortably above every
  single-call latency observed here.
- **Playbook coverage doesn't show an obvious token-count or latency signal on its own** in this
  small sample (5 incidents) — #3 (no playbook) and #1 (has playbook) have similar draft token
  counts. The KB-coverage effect `hallucination-eval.md` documented is in *hallucination content*
  (fabricated specifics filling the gap), not necessarily *token volume* — a fabricated detail
  and a grounded one can be similar length. One signal that did show up: #5 (T1218.005, no
  playbook) retrieved only 2 chunks vs. 4–5 for every other case, meaning less context to ground
  against in the first place.

## What this means for the free tier

"Cost" here is entirely a rate-limit/quota question, not a dollar figure — both Gemini and Groq's
free tiers are $0 (see the project's `docs/decisions.md` LLM-provider entries). Gemini's 20
requests/day cap means **at most 10 explanations per day** on the default provider (2 calls
each) before hitting `LLMProviderError` (now surfaced as a clean `503`, not a generic 500 — see
the Day 12 LLM-robustness decision). This run itself hit that exact wall: Gemini's quota was
already exhausted from earlier the same day before this script could get a single successful
call through, which is why it was run against Groq instead — the same fallback the Day 10
hallucination spot-check used, and the reason `llm_client.py` supports switching providers via
`LLM_PROVIDER` in the first place. For anything beyond light manual testing (a demo day, a
testing sprint), Groq's higher-throughput free tier is the practical choice; Gemini remains the
project default for normal/light use.

## Follow-up (not implemented in Day 12)

Per `docs/research/hallucination-eval.md` finding #3, adding the 3 missing KB playbooks (T1105,
T1546.012, T1218.005) is expected to reduce hallucinated "Recommended next steps" content the
most of any available lever — that's KB *content* work (`data/knowledge_base/`), out of Day 12's
scope (its Files column is `api/routes_chat.py`, `rag/prompts.py`, `rag/llm_client.py`,
`docs/llm-cost-latency.md`). Flagged here as the natural next measurement to re-run once those
playbooks exist, to see whether retrieval/token patterns shift alongside the hallucination-rate
improvement.
