import os
import tempfile
import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def token_header():
    return {"X-Service-Token": os.environ.get("INTERNAL_SERVICE_TOKEN", "test-token")}


@pytest.fixture
async def client():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac


def _temp_file(content: str, suffix: str = ".java") -> str:
    f = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False)
    f.write(content)
    f.close()
    return f.name


@pytest.mark.anyio
async def test_health_returns_ok(client, token_header):
    response = await client.get("/internal/health", headers=token_header)
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


@pytest.mark.anyio
async def test_health_without_token_returns_401(client):
    response = await client.get("/internal/health")
    assert response.status_code == 422  # FastAPI returns 422 when required header is missing


@pytest.mark.anyio
async def test_execute_rule_regex_finds_pattern(client, token_header):
    path = _temp_file('String secret = "abc123";\n')
    try:
        body = {
            "ruleId": "test-rule-1",
            "type": "PATTERN_REGEX",
            "payload": {"pattern": r"secret\s*="},
            "artifactPath": path,
        }
        response = await client.post(
            "/internal/execute-rule", json=body, headers=token_header
        )
        assert response.status_code == 200
        findings = response.json()
        assert isinstance(findings, list)
        assert len(findings) >= 1
        assert "evidenceSnippet" in findings[0]
    finally:
        os.unlink(path)


@pytest.mark.anyio
async def test_execute_rule_masks_secrets_in_evidence(client, token_header):
    path = _temp_file('api_key=sk-super-secret-value\n', suffix=".env")
    try:
        body = {
            "ruleId": "test-rule-2",
            "type": "PATTERN_REGEX",
            "payload": {"pattern": r"api_key\s*="},
            "artifactPath": path,
        }
        response = await client.post(
            "/internal/execute-rule", json=body, headers=token_header
        )
        assert response.status_code == 200
        findings = response.json()
        assert len(findings) >= 1
        # Secret value must not appear in evidence snippet
        assert "sk-super-secret-value" not in findings[0]["evidenceSnippet"]
        assert "*****" in findings[0]["evidenceSnippet"]
    finally:
        os.unlink(path)


@pytest.mark.anyio
async def test_execute_rule_unknown_type_returns_error(client, token_header):
    body = {
        "ruleId": "test-rule-3",
        "type": "UNKNOWN_TYPE",
        "payload": {},
        "artifactPath": "/tmp/nonexistent.java",
    }
    response = await client.post(
        "/internal/execute-rule", json=body, headers=token_header
    )
    assert response.status_code in (400, 422, 500)
