"""Structured JSON logging (Day 12).

Stdlib-only -- no new dependency, consistent with the project's $0 policy
(see docs/decisions.md). Every existing `logger = logging.getLogger(__name__)`
call across the codebase (ingest, detection, incident/alert/event services)
starts emitting one JSON object per line once `configure_logging()` runs,
with no change to those call sites -- this only replaces the root logger's
handler/formatter.
"""

import json
import logging

_CONFIGURED = False


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def configure_logging(level: int = logging.INFO) -> None:
    """Idempotent -- safe to call more than once (e.g. app import + tests
    both importing app.main) without stacking duplicate handlers.
    """
    global _CONFIGURED
    if _CONFIGURED:
        return

    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())

    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)

    _CONFIGURED = True
