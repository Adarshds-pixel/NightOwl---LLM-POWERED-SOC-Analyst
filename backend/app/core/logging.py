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
import sys

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
        # ensure_ascii escapes anything outside ASCII rather than emitting it
        # raw. Log lines stay machine-readable on any stream encoding, and a
        # model response containing, say, a non-breaking hyphen cannot make
        # the log record itself unwritable.
        return json.dumps(payload, ensure_ascii=True)


def configure_logging(level: int = logging.INFO) -> None:
    """Idempotent -- safe to call more than once (e.g. app import + tests
    both importing app.main) without stacking duplicate handlers.
    """
    global _CONFIGURED
    if _CONFIGURED:
        return

    # Windows consoles default to a legacy code page (cp1252), and a
    # StreamHandler bound to that stdout raises UnicodeEncodeError on any
    # character outside it. LLM responses routinely contain typographic
    # dashes and quotes, so an un-reconfigured stream turned a perfectly
    # good /explain response into a 500. Force UTF-8 on the stream where the
    # runtime allows it, and drop anything still unencodable rather than
    # letting logging break a request.
    stream = sys.stdout
    reconfigure = getattr(stream, "reconfigure", None)
    if reconfigure is not None:
        try:
            reconfigure(encoding="utf-8", errors="backslashreplace")
        except (ValueError, OSError):
            # Stream does not support reconfiguration (already detached, or
            # replaced by a non-text wrapper) -- ensure_ascii above still
            # keeps the payload writable.
            pass

    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())

    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)

    _CONFIGURED = True
