"""Loads the official MITRE ATT&CK Enterprise STIX/JSON dataset into a
technique lookup table, keyed by technique ID (e.g. "T1059.001").

Pinned to release tag ATT&CK-v19.2 (not `master`) so every teammate and
the final demo use an identical, frozen dataset for the whole project --
MITRE ships new versions every few months, well outside this project's
timeline, and an unpinned rolling dataset risks a technique ID
appearing/disappearing mid-project.

Deprecated/revoked techniques are kept in the lookup (tagged, not
dropped) so Pair 1's Day 11 rule-to-technique validator can decide its
own policy on them instead of silently losing data here.
"""

import json
from pathlib import Path

import requests

MITRE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v19.2/"
    "enterprise-attack/enterprise-attack.json"
)
MITRE_CACHE_PATH = Path(__file__).resolve().parents[3] / "ai" / "mitre" / "enterprise-attack.json"


class MitreDatasetDownloadError(Exception):
    pass


def download_dataset(
    url: str = MITRE_ATTACK_URL,
    dest: Path = MITRE_CACHE_PATH,
    force: bool = False,
) -> Path:
    if dest.exists() and not force:
        return dest

    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        resp = requests.get(url, stream=True, timeout=30)
        resp.raise_for_status()
    except requests.RequestException as e:
        raise MitreDatasetDownloadError(f"failed to download MITRE dataset: {e}") from e

    tmp_path = dest.with_suffix(".json.tmp")
    with open(tmp_path, "wb") as f:
        for chunk in resp.iter_content(chunk_size=8192):
            f.write(chunk)
    tmp_path.replace(dest)
    return dest


def load_raw_bundle(path: Path = MITRE_CACHE_PATH) -> dict:
    if not path.exists():
        download_dataset(dest=path)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


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


_lookup_cache: dict[str, dict] | None = None


def load_mitre_techniques(force_refresh: bool = False) -> dict[str, dict]:
    global _lookup_cache
    if _lookup_cache is None or force_refresh:
        bundle = load_raw_bundle() if not force_refresh else load_raw_bundle(
            download_dataset(force=True)
        )
        _lookup_cache = parse_techniques(bundle)
    return _lookup_cache


if __name__ == "__main__":
    techniques = load_mitre_techniques()
    print(f"Loaded {len(techniques)} techniques")
    t1059_001 = techniques.get("T1059.001")
    if t1059_001:
        print(f"T1059.001 -> {t1059_001['name']} (tactics: {t1059_001['tactics']})")
