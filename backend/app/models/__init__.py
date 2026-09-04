"""Import all models so Base.metadata sees every table (needed for Alembic
autogenerate and for create_all() in tests)."""

from app.models.ai_opinion import AiOpinion
from app.models.alert import Alert
from app.models.audit_log import AuditLog
from app.models.chat_message import ChatMessage
from app.models.event import Event
from app.models.incident import Incident
from app.models.rule import Rule

__all__ = ["AiOpinion", "Alert", "AuditLog", "ChatMessage", "Event", "Incident", "Rule"]
