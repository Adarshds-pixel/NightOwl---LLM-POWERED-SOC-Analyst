"""GET /system/status -- what is actually configured and loaded, for the
console's status indicators.

`/health` only proves the API process answers. The UI used to show "AI online"
from that alone, while the LLM key could be missing, the knowledge base never
built, or the ML model absent. This reports each component's real state
without making a paid LLM call and without exposing any secret.
"""

from fastapi import APIRouter
from pydantic import BaseModel

from app.core.config import settings
from app.detection.rule_loader import get_loaded_rules
from app.detection.sequences import SEQUENCE_PATTERNS
from app.mitre.loader import ATTACK_RELEASE, load_mitre_techniques

router = APIRouter()


class ComponentStatus(BaseModel):
    ready: bool
    detail: str


class SystemStatusResponse(BaseModel):
    environment: str
    llm: ComponentStatus
    knowledge_base: ComponentStatus
    detection_rules: ComponentStatus
    ml_anomaly_layer: ComponentStatus
    attack_dataset: ComponentStatus
    demo_mode_enabled: bool


def _knowledge_base_status() -> ComponentStatus:
    try:
        from app.rag.chroma_client import get_or_create_collection
        from app.rag.retriever import KB_COLLECTION_NAME

        count = get_or_create_collection(KB_COLLECTION_NAME).count()
    except Exception as exc:  # noqa: BLE001 -- a status probe must not 500
        return ComponentStatus(ready=False, detail=f"unavailable ({type(exc).__name__})")
    if count == 0:
        return ComponentStatus(ready=False, detail="empty -- run ai/tools/build_kb.py")
    return ComponentStatus(ready=True, detail=f"{count} chunks indexed")


def _ml_status() -> ComponentStatus:
    from app.ml.runtime import get_detector_status

    ready, detail = get_detector_status()
    return ComponentStatus(ready=ready, detail=detail)


@router.get("/system/status", response_model=SystemStatusResponse)
def system_status() -> SystemStatusResponse:
    rules = get_loaded_rules()
    return SystemStatusResponse(
        environment="local" if settings.is_local else "production",
        llm=ComponentStatus(
            ready=bool(settings.groq_api_key),
            detail=f"Groq ({settings.groq_model})" if settings.groq_api_key else "GROQ_API_KEY is not set",
        ),
        knowledge_base=_knowledge_base_status(),
        detection_rules=ComponentStatus(
            ready=bool(rules),
            detail=f"{len(rules)} Sigma-style rules + {len(SEQUENCE_PATTERNS)} sequence detectors",
        ),
        ml_anomaly_layer=_ml_status(),
        attack_dataset=ComponentStatus(
            ready=True, detail=f"{ATTACK_RELEASE}, {len(load_mitre_techniques())} techniques"
        ),
        demo_mode_enabled=settings.demo_mode_enabled,
    )
