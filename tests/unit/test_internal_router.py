import os
import threading
import time

import pytest


def _write(tmp_path, name: str, content: str) -> str:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return str(path)


def test_health_returns_ok(client, auth_headers):
    response = client.get("/internal/health", headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_health_without_token_is_rejected(client):
    response = client.get("/internal/health")
    assert response.status_code == 422  # FastAPI returns 422 when the required header is missing


def test_wrong_token_returns_401(client):
    response = client.get("/internal/health", headers={"X-Service-Token": "wrong"})
    assert response.status_code == 401


def test_execute_rule_regex_finds_pattern(client, auth_headers, tmp_path):
    path = _write(tmp_path, "A.java", 'String secret = "abc123";\n')
    response = client.post("/internal/execute-rule", headers=auth_headers, json={
        "ruleId": "test-rule-1",
        "type": "PATTERN_REGEX",
        "payload": {"pattern": r"secret\s*="},
        "artifactPath": path,
    })
    assert response.status_code == 200
    findings = response.json()["findings"]
    assert len(findings) == 1
    assert findings[0]["filePath"] == path


def test_execute_rule_masks_secrets_in_evidence(client, auth_headers, tmp_path):
    path = _write(tmp_path, "app.env", "api_key=sk-super-secret-value\n")
    response = client.post("/internal/execute-rule", headers=auth_headers, json={
        "ruleId": "test-rule-2",
        "type": "PATTERN_REGEX",
        "payload": {"pattern": r"api_key\s*="},
        "artifactPath": path,
    })
    assert response.status_code == 200
    findings = response.json()["findings"]
    assert len(findings) == 1
    assert "sk-super-secret-value" not in findings[0]["evidenceSnippet"]
    assert "*****" in findings[0]["evidenceSnippet"]


def test_execute_rule_unknown_type_returns_controlled_error(client, auth_headers):
    response = client.post("/internal/execute-rule", headers=auth_headers, json={
        "ruleId": "test-rule-3",
        "type": "UNKNOWN_TYPE",
        "payload": {},
        "artifactPath": "/tmp/nonexistent.java",
    })
    assert response.status_code == 200
    body = response.json()
    assert body["findings"] == []
    assert body["errors"][0]["errorCode"] == "UNKNOWN_RULE_TYPE"


def test_batch_returns_findings_and_errors_per_file(client, auth_headers, tmp_path):
    vulnerable = _write(tmp_path, "Dao.java", 'String q = "x";\npassword = "p"\n')
    clean = _write(tmp_path, "Clean.java", "class Clean {}\n")
    missing = str(tmp_path / "missing.java")

    response = client.post("/internal/execute-rule-batch", headers=auth_headers, json={
        "ruleId": "rule-batch",
        "type": "PATTERN_REGEX",
        "payload": {"pattern": r"password\s*="},
        "artifactPaths": [vulnerable, clean, missing],
        "category": "AUTHENTICATION_FAILURE",
        "severity": "HIGH",
    })

    assert response.status_code == 200
    body = response.json()
    assert [(f["filePath"], f["lineNumber"]) for f in body["findings"]] == [(vulnerable, 2)]
    assert body["findings"][0]["severity"] == "HIGH"
    assert [(e["filePath"], e["errorCode"]) for e in body["errors"]] == [(missing, "FILE_NOT_FOUND")]


def test_batch_rejects_empty_file_list(client, auth_headers):
    response = client.post("/internal/execute-rule-batch", headers=auth_headers, json={
        "ruleId": "r", "type": "PATTERN_REGEX", "payload": {"pattern": "x"}, "artifactPaths": [],
    })
    assert response.status_code == 422


def test_batch_stops_when_the_batch_budget_is_spent(client, auth_headers, tmp_path, monkeypatch):
    monkeypatch.setenv("BATCH_TIMEOUT_SECONDS", "0")
    paths = [_write(tmp_path, f"f{i}.java", "password = 1\n") for i in range(3)]
    response = client.post("/internal/execute-rule-batch", headers=auth_headers, json={
        "ruleId": "r", "type": "PATTERN_REGEX", "payload": {"pattern": "password"}, "artifactPaths": paths,
    })
    body = response.json()
    assert body["findings"] == []
    assert {e["errorCode"] for e in body["errors"]} == {"BATCH_TIMEOUT"}
    assert len(body["errors"]) == 3


def test_slow_rule_does_not_block_other_requests(client, auth_headers, tmp_path, monkeypatch):
    """A rule stuck in backtracking used to freeze the whole engine (sync code inside an
    async endpoint, plus re holding the GIL). Now health keeps answering meanwhile."""
    monkeypatch.setattr("app.executors.limits.RULE_TIMEOUT_SECONDS", 3)
    path = _write(tmp_path, "slow.txt", "a" * 60 + "b\n")
    result = {}

    def slow_call():
        result["response"] = client.post("/internal/execute-rule", headers=auth_headers, json={
            "ruleId": "slow", "type": "PATTERN_REGEX", "payload": {"pattern": r"^(a|aa)+$"},
            "artifactPath": path,
        })

    worker = threading.Thread(target=slow_call)
    worker.start()
    time.sleep(0.3)
    started = time.monotonic()
    health = client.get("/internal/health", headers=auth_headers)
    health_seconds = time.monotonic() - started
    worker.join(timeout=10)

    assert health.status_code == 200
    assert health_seconds < 1.5
    assert result["response"].json()["errors"][0]["errorCode"] == "RULE_TIMEOUT"


def test_path_outside_sandbox_is_refused(client, auth_headers, tmp_path, monkeypatch):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    outside = _write(tmp_path, "secret.txt", "password = hunter2\n")
    monkeypatch.setenv("SANDBOX_ROOT", str(sandbox))

    response = client.post("/internal/execute-rule-batch", headers=auth_headers, json={
        "ruleId": "r", "type": "PATTERN_REGEX", "payload": {"pattern": "password"},
        "artifactPaths": [outside, str(sandbox / ".." / "secret.txt")],
    })
    body = response.json()
    assert body["findings"] == []
    assert [e["errorCode"] for e in body["errors"]] == ["PATH_OUTSIDE_SANDBOX"] * 2


def test_symlink_leaving_the_sandbox_is_refused(client, auth_headers, tmp_path, monkeypatch):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    target = _write(tmp_path, "environ", "INTERNAL_SERVICE_TOKEN=abc\n")
    link = sandbox / "config.yml"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not available on this system")
    inside = _write(sandbox, "ok.txt", "password = 1\n")
    monkeypatch.setenv("SANDBOX_ROOT", str(sandbox))

    response = client.post("/internal/execute-rule-batch", headers=auth_headers, json={
        "ruleId": "r", "type": "PATTERN_REGEX", "payload": {"pattern": "TOKEN|password"},
        "artifactPaths": [str(link), inside],
    })
    body = response.json()
    assert [f["filePath"] for f in body["findings"]] == [inside]
    assert [(e["filePath"], e["errorCode"]) for e in body["errors"]] == [(str(link), "PATH_OUTSIDE_SANDBOX")]
