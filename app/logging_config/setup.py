"""JSON logs of the engine, with the same base fields as the backend's (logback-spring.xml).

One JSON object per line::

    {"timestamp": "2026-11-12T15:04:05.123456Z", "level": "INFO", "traceId": "...",
     "message": "execute_rule_batch_completed", "logger": "app.routers.internal",
     "context": {"service": "pdgseg-engine", "ruleId": "...", "findingsCount": 3}}

``traceId`` is the one the backend sends in X-Trace-Id (TraceIdFilter there), so a backend
log line and the engine lines of the same analysis share it. The middleware in app.main binds
it to the request's context, so every log of that request carries it, including those written
by the executors in the thread pool. Extra key-values go under ``context``; a traceback goes in
``stackTrace``. Every string is masked (passwords, tokens, Bearer headers) before it is written.
"""

import logging
import re
import sys
import uuid
from typing import Any, Optional, TextIO

import structlog
from fastapi import Request

from app.masking.secret_masker import SecretMasker

SERVICE = "pdgseg-engine"
TRACE_HEADER = "X-Trace-Id"

# UUID or any 8-64 character id of letters, digits and dashes (same rule as the backend's
# TraceIdFilter): any other value could forge log lines, so it is replaced.
_SAFE_TRACE_ID = re.compile(r"[A-Za-z0-9-]{8,64}")

_BASE_FIELDS = ("timestamp", "level", "traceId", "message", "logger")

# Same level names as Logback.
_LEVELS = {"warning": "WARN", "critical": "ERROR", "exception": "ERROR", "fatal": "ERROR"}

_masker = SecretMasker()

# On top of SecretMasker's key=value patterns: secrets recognizable by their shape.
_SECRET_SHAPES = [
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9\-._~+/]{16,}=*"), r"\g<1>*****"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "*****"),
    (re.compile(r"\bpdgseg_[A-Za-z0-9_-]{20,}"), "*****"),
    (re.compile(r"(://[^/\s:@]+:)[^@\s/]+(@)"), r"\g<1>*****\g<2>"),
]


def resolve_trace_id(header_value: Optional[str]) -> str:
    if header_value and _SAFE_TRACE_ID.fullmatch(header_value):
        return header_value
    return str(uuid.uuid4())


def get_trace_id(request: Request) -> str:
    """The request's traceId: the one the middleware resolved, or one from its header."""
    trace_id = getattr(request.state, "trace_id", None)
    return trace_id or resolve_trace_id(request.headers.get(TRACE_HEADER))


def mask_secrets(text: str) -> str:
    masked = _masker.mask(text)
    for pattern, replacement in _SECRET_SHAPES:
        masked = pattern.sub(replacement, masked)
    return masked


def _normalize_level(_, __, event_dict: dict) -> dict:
    level = str(event_dict.get("level", "info")).lower()
    event_dict["level"] = _LEVELS.get(level, level.upper())
    return event_dict


def _rename_exception(_, __, event_dict: dict) -> dict:
    if "exception" in event_dict:
        event_dict["stackTrace"] = event_dict.pop("exception")
    return event_dict


def _nest_context(_, __, event_dict: dict) -> dict:
    """Base fields first, in a fixed order; everything else under "context"."""
    ordered: dict[str, Any] = {key: event_dict.pop(key) for key in _BASE_FIELDS if key in event_dict}
    stack_trace = event_dict.pop("stackTrace", None)
    ordered["context"] = {"service": SERVICE, **event_dict}
    if stack_trace:
        ordered["stackTrace"] = stack_trace
    return ordered


def _mask(value: Any) -> Any:
    if isinstance(value, str):
        return mask_secrets(value)
    if isinstance(value, dict):
        return {key: _mask(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_mask(item) for item in value]
    return value


def _mask_values(_, __, event_dict: dict) -> dict:
    return _mask(event_dict)


def configure_logging(stream: Optional[TextIO] = None, level: int = logging.INFO) -> None:
    """Every log, structlog's and the standard library's (uvicorn included), as JSON lines."""
    shared = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        _normalize_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True, key="timestamp"),
    ]
    structlog.configure(
        processors=[*shared, structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=False,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.processors.format_exc_info,
            _rename_exception,
            structlog.processors.EventRenamer("message"),
            _nest_context,
            _mask_values,
            structlog.processors.JSONRenderer(ensure_ascii=False),
        ],
    )
    handler = logging.StreamHandler(stream or sys.stdout)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)

    # uvicorn installs its own text handlers; its logs go through the root (JSON) instead.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        uvicorn_logger = logging.getLogger(name)
        uvicorn_logger.handlers = []
        uvicorn_logger.propagate = True
    # The access log has no traceId (it is written outside the request); the middleware logs
    # each request with it instead.
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
