"""JSON logs of the engine: the backend's base fields, the backend's traceId and no secrets."""
import io
import json
import logging

import pytest
import structlog
from fastapi.testclient import TestClient

from app.logging_config.setup import configure_logging, mask_secrets, resolve_trace_id
from app.main import app


@pytest.fixture
def log_stream():
    stream = io.StringIO()
    configure_logging(stream=stream, level=logging.DEBUG)
    yield stream
    configure_logging()


def _lines(stream: io.StringIO) -> list[dict]:
    return [json.loads(line) for line in stream.getvalue().splitlines() if line.strip()]


def test_every_log_of_a_request_has_the_base_fields_and_the_backend_trace_id(log_stream, tmp_path):
    target = tmp_path / "App.java"
    target.write_text('String q = "SELECT * FROM users";\n', encoding="utf-8")
    trace_id = "6f1c2a8e-3f0b-4a59-9d6e-0c2b7d1e4f5a"

    with TestClient(app) as client:
        configure_logging(stream=log_stream, level=logging.DEBUG)  # the lifespan configured stdout
        response = client.post(
            "/internal/execute-rule-batch",
            headers={"X-Service-Token": "test-internal-token", "X-Trace-Id": trace_id},
            json={"ruleId": "r-1", "type": "PATTERN_REGEX", "payload": {"pattern": "SELECT \\\\* FROM"},
                  "artifactPaths": [str(target)], "category": "SQL_INJECTION", "severity": "MEDIUM"},
        )

    assert response.status_code == 200
    assert response.headers["X-Trace-Id"] == trace_id
    # The test client's own logs (its event loop, its HTTP call) are not the engine's.
    lines = [line for line in _lines(log_stream) if line["logger"] not in {"asyncio", "httpx"}]
    messages = [line["message"] for line in lines]
    assert "execute_rule_batch_started" in messages
    assert "execute_rule_batch_completed" in messages
    assert "request_completed" in messages
    for line in lines:
        assert list(line)[:5] == ["timestamp", "level", "traceId", "message", "logger"], line
        assert line["timestamp"].endswith("Z")
        assert line["level"] in {"DEBUG", "INFO", "WARN", "ERROR"}
        assert line["traceId"] == trace_id
        assert line["context"]["service"] == "pdgseg-engine"


def test_a_trace_id_that_could_forge_log_lines_is_replaced():
    assert resolve_trace_id('x"}{"level":"ERROR') != 'x"}{"level":"ERROR'
    assert resolve_trace_id(None)
    assert resolve_trace_id("trace-test-001") == "trace-test-001"


def test_secrets_never_reach_the_log(log_stream):
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.c2lnbmF0dXJlLXNpZ25hdHVyZQ"
    logger = structlog.get_logger("app.test")
    logger.warning("login password=Sup3rS3creta! Authorization: Bearer " + jwt, header="Bearer " + jwt)
    try:
        raise ValueError("token=abc123def456 en la conexión")
    except ValueError:
        logger.exception("fallo")
    logging.getLogger("uvicorn.error").error("api_key=AKIAEXAMPLEKEY123")

    output = log_stream.getvalue()
    for secret in ("Sup3rS3creta!", jwt, "abc123def456", "AKIAEXAMPLEKEY123"):
        assert secret not in output
    lines = _lines(log_stream)
    assert lines[1]["level"] == "ERROR"
    assert "ValueError" in lines[1]["stackTrace"]
    assert lines[2]["logger"] == "uvicorn.error"


def test_mask_secrets_leaves_ordinary_text_alone():
    assert mask_secrets("execute_rule_batch_completed findingsCount=3") == "execute_rule_batch_completed findingsCount=3"
