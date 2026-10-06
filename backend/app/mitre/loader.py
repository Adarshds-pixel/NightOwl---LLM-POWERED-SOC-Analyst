"""MITRE ATT&CK Enterprise technique lookup, keyed by technique ID
(e.g. "T1059.001").

Pinned to release ATT&CK-v19.2 so every environment uses an identical,
frozen dataset. The technique index (id, name, description, tactics,
deprecated/revoked flags) and the list of valid tactic short-names ship with
the code in `data/enterprise_attack_v19_2.json.gz`, extracted from the
official `mitre/cti` STIX bundle. Nothing here touches the network:

* the app, the rule validator and the test suite work offline and on a fresh
  clone (the 47 MB bundle used to be downloaded on first use from GitHub,
  from inside a request, with no lock -- two concurrent first requests raced
  on the same temp file, and with no network /mitre/techniques returned 500);
* the knowledge-base builder (ai/tools/build_kb.py) reads the same index.

To move to a newer ATT&CK release, run `python -m app.mitre.loader --rebuild
<path-to-enterprise-attack.json>` and review the rule validator's output.

Deprecated/revoked techniques are kept in the lookup (tagged, not dropped) so
the rule-to-technique validator can decide its own policy on them.
"""

import gzip
import json
import threading
from pathlib import Path

ATTACK_RELEASE = "ATT&CK-v19.2"
MITRE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v19.2/"
    "enterprise-attack/enterprise-attack.json"
)
VENDORED_INDEX_PATH = Path(__file__).resolve().parent / "data" / "enterprise_attack_v19_2.json.gz"

_lock = threading.Lock()
_index: dict | None = None


def _extract_technique_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _extract_tactics(obj: dict) -> list[str]:
    return [
        phase["phase_name"]
        for phase in obj.get("kill_chain_phases", [])
        if phase.get("kill_chain_name") == "mitre-attack"
    ]


def parse_techniques(bundle: dict) -> dict[str, dict]:
    """STIX bundle -> {technique_id: {...}}. Used to (re)build the index."""
    lookup: dict[str, dict] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        tech_id = _extract_technique_id(obj)
        if not tech_id:
            continue
        lookup[tech_id] = {
            "id": tech_id,
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "tactics": _extract_tactics(obj),
            "is_deprecated": bool(obj.get("x_mitre_deprecated", False)),
            "is_revoked": bool(obj.get("revoked", False)),
        }
    return lookup


def parse_tactics(bundle: dict) -> list[str]:
    return sorted(
        {
            obj["x_mitre_shortname"]
            for obj in bundle.get("objects", [])
            if obj.get("type") == "x-mitre-tactic" and not obj.get("revoked") and not obj.get("x_mitre_deprecated")
        }
    )


def _load_index() -> dict:
    global _index
    if _index is not None:
        return _index
    with _lock:
        if _index is None:
            with gzip.open(VENDORED_INDEX_PATH, "rt", encoding="utf-8") as f:
                _index = json.load(f)
    return _index


def load_mitre_techniques(force_refresh: bool = False) -> dict[str, dict]:
    """{technique_id: {id, name, description, tactics, is_deprecated, is_revoked}}."""
    global _index
    if force_refresh:
        with _lock:
            _index = None
    return _load_index()["techniques"]


def load_mitre_tactics() -> list[str]:
    """Valid tactic short-names in this release (e.g. "credential-access",
    "stealth"). ATT&CK v19 split the old "defense-evasion" tactic into
    "stealth" and "defense-impairment"."""
    return list(_load_index()["tactics"])


def rebuild_index(bundle_path: Path, dest: Path = VENDORED_INDEX_PATH) -> int:
    with open(bundle_path, "r", encoding="utf-8") as f:
        bundle = json.load(f)
    payload = {
        "source": f"mitre/cti {ATTACK_RELEASE} enterprise-attack.json",
        "tactics": parse_tactics(bundle),
        "techniques": parse_techniques(bundle),
    }
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(gzip.compress(raw, 9, mtime=0))
    return len(payload["techniques"])


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rebuild", type=Path, help="path to an enterprise-attack.json STIX bundle")
    args = parser.parse_args()
    if args.rebuild:
        print(f"wrote {rebuild_index(args.rebuild)} techniques to {VENDORED_INDEX_PATH}")
    techniques = load_mitre_techniques()
    print(f"Loaded {len(techniques)} techniques; tactics: {', '.join(load_mitre_tactics())}")
