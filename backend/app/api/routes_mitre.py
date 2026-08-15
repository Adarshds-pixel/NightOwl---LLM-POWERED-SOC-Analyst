"""GET /mitre/techniques -- returns the full MITRE ATT&CK technique catalog
(Day 6 Pair 2). Consumed by the Day 16 heatmap (technique + tactic columns)
and by Pair 1's Day 11 rule-to-technique validator (mitre/validator.py).

Thin passthrough over mitre/loader.py's cached lookup -- no server-side
filtering of deprecated/revoked techniques, since different consumers
(heatmap vs. validator) may want different policies on them; each flag
is included on every entry so callers can filter themselves.
"""

from fastapi import APIRouter
from pydantic import BaseModel

from app.mitre.loader import load_mitre_techniques

router = APIRouter()


class MitreTechnique(BaseModel):
    id: str
    name: str
    description: str
    tactics: list[str]
    is_deprecated: bool
    is_revoked: bool


class MitreTechniquesResponse(BaseModel):
    techniques: list[MitreTechnique]
    count: int


@router.get("/mitre/techniques", response_model=MitreTechniquesResponse)
def get_mitre_techniques() -> MitreTechniquesResponse:
    techniques = [
        MitreTechnique(**technique)
        for technique in sorted(load_mitre_techniques().values(), key=lambda t: t["id"])
    ]
    return MitreTechniquesResponse(techniques=techniques, count=len(techniques))
