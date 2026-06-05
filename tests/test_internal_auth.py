def test_execute_rule_invalid_token_returns_401(client):
    payload = {
        "ruleId": "rule-1",
        "type": "PATTERN_REGEX",
        "payload": {"pattern": "secret"},
        "artifactPath": "/tmp/none",
    }
    response = client.post(
        "/internal/execute-rule",
        headers={"X-Service-Token": "invalid-token"},
        json=payload,
    )
    assert response.status_code == 401
