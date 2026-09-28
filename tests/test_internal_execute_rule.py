def test_execute_rule_masks_secret_in_evidence(client, auth_headers, tmp_path):
    artifact = tmp_path / "secret.txt"
    artifact.write_text("password = abc123\n", encoding="utf-8")

    payload = {
        "ruleId": "rule-1",
        "type": "PATTERN_REGEX",
        "payload": {"pattern": r"password\s*="},
        "artifactPath": str(artifact),
        "policyId": "policy-1",
        "category": "credentials",
        "severity": "HIGH",
        "cweId": "CWE-798",
    }
    response = client.post("/internal/execute-rule", headers=auth_headers, json=payload)

    assert response.status_code == 200
    body = response.json()
    assert body["errors"] == []
    assert len(body["findings"]) == 1
    assert "*****" in body["findings"][0]["evidenceSnippet"]
    assert "abc123" not in body["findings"][0]["evidenceSnippet"]


def test_execute_rule_no_matches_returns_empty_findings(client, auth_headers, tmp_path):
    artifact = tmp_path / "clean.txt"
    artifact.write_text("nothing to see\n", encoding="utf-8")
    payload = {
        "ruleId": "rule-2",
        "type": "PATTERN_REGEX",
        "payload": {"pattern": r"password\s*="},
        "artifactPath": str(artifact),
    }
    response = client.post("/internal/execute-rule", headers=auth_headers, json=payload)

    assert response.status_code == 200
    body = response.json()
    assert body["findings"] == []
    assert body["errors"] == []


def test_execute_rule_missing_file_returns_controlled_error(client, auth_headers):
    payload = {
        "ruleId": "rule-3",
        "type": "PATTERN_REGEX",
        "payload": {"pattern": r"password\s*="},
        "artifactPath": "/tmp/not-found-file",
    }
    response = client.post("/internal/execute-rule", headers=auth_headers, json=payload)

    assert response.status_code == 200
    body = response.json()
    assert body["findings"] == []
    assert len(body["errors"]) == 1
    assert body["errors"][0]["errorType"] == "FILE_NOT_FOUND"
    assert body["errors"][0]["errorCode"] == "FILE_NOT_FOUND"
