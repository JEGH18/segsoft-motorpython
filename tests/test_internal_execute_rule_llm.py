from unittest.mock import AsyncMock, patch


def test_llm_disabled_by_default_leaves_suggestedAction_none(client, auth_headers, tmp_path, monkeypatch):
    monkeypatch.delenv("LLM_SUGGESTIONS_ENABLED", raising=False)
    artifact = tmp_path / "code.py"
    artifact.write_text("query = 'SELECT * FROM users WHERE id=' + id\n" * 3, encoding="utf-8")

    payload = {
        "ruleId": "rule-1",
        "type": "PATTERN_REGEX",
        "payload": {"pattern": r"query\s*=", "suggestedAction": "Usa consultas parametrizadas."},
        "artifactPath": str(artifact),
        "category": "SQL_INJECTION",
        "cweId": "CWE-89",
    }
    response = client.post("/internal/execute-rule", headers=auth_headers, json=payload)

    assert response.status_code == 200
    body = response.json()
    assert len(body["findings"]) == 3
    # Unchanged from today: the engine never fills suggestedAction unless
    # the flag is on -- Java's static-text fallback is what shows something.
    assert all(f["suggestedAction"] is None for f in body["findings"])


def test_llm_enabled_calls_once_per_rule_and_applies_to_all_matches(client, auth_headers, tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_SUGGESTIONS_ENABLED", "true")
    monkeypatch.setenv("LLM_API_KEY", "sk-test-key")
    artifact = tmp_path / "code.py"
    # Three matches of the SAME pattern -- must produce exactly ONE LLM call,
    # not three, and every finding gets that one suggestion.
    artifact.write_text("query = 'SELECT * FROM users WHERE id=' + id\n" * 3, encoding="utf-8")

    payload = {
        "ruleId": "rule-1",
        "type": "PATTERN_REGEX",
        "payload": {"pattern": r"query\s*=", "suggestedAction": "Usa consultas parametrizadas."},
        "artifactPath": str(artifact),
        "category": "SQL_INJECTION",
        "cweId": "CWE-89",
    }

    with patch(
        "app.routers.internal.suggestion_generator.generate_suggestion",
        new=AsyncMock(return_value="Usa PreparedStatement con parámetros bindeados."),
    ) as mock_generate:
        response = client.post("/internal/execute-rule", headers=auth_headers, json=payload)

    assert response.status_code == 200
    body = response.json()
    assert len(body["findings"]) == 3
    assert all(
        f["suggestedAction"] == "Usa PreparedStatement con parámetros bindeados."
        for f in body["findings"]
    )
    mock_generate.assert_awaited_once()
    _, kwargs = mock_generate.call_args
    assert kwargs["category"] == "SQL_INJECTION"
    assert kwargs["cwe_id"] == "CWE-89"
    assert kwargs["style_example"] == "Usa consultas parametrizadas."


def test_llm_enabled_but_no_matches_never_calls_generate_suggestion(client, auth_headers, tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_SUGGESTIONS_ENABLED", "true")
    monkeypatch.setenv("LLM_API_KEY", "sk-test-key")
    artifact = tmp_path / "clean.py"
    artifact.write_text("print('nothing suspicious here')\n", encoding="utf-8")

    payload = {
        "ruleId": "rule-2",
        "type": "PATTERN_REGEX",
        "payload": {"pattern": r"query\s*="},
        "artifactPath": str(artifact),
    }

    with patch(
        "app.routers.internal.suggestion_generator.generate_suggestion", new=AsyncMock()
    ) as mock_generate:
        response = client.post("/internal/execute-rule", headers=auth_headers, json=payload)

    assert response.status_code == 200
    assert response.json()["findings"] == []
    mock_generate.assert_not_awaited()


def test_llm_failure_falls_back_to_none_and_does_not_break_the_response(client, auth_headers, tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_SUGGESTIONS_ENABLED", "true")
    monkeypatch.setenv("LLM_API_KEY", "sk-test-key")
    artifact = tmp_path / "code.py"
    artifact.write_text("query = 'SELECT * FROM users WHERE id=' + id\n", encoding="utf-8")

    payload = {
        "ruleId": "rule-3",
        "type": "PATTERN_REGEX",
        "payload": {"pattern": r"query\s*="},
        "artifactPath": str(artifact),
    }

    # generate_suggestion itself never raises (see its own tests) -- but this
    # confirms the router doesn't assume a non-None result either.
    with patch(
        "app.routers.internal.suggestion_generator.generate_suggestion",
        new=AsyncMock(return_value=None),
    ):
        response = client.post("/internal/execute-rule", headers=auth_headers, json=payload)

    assert response.status_code == 200
    body = response.json()
    assert len(body["findings"]) == 1
    assert body["findings"][0]["suggestedAction"] is None
