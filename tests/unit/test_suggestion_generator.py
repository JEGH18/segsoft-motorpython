from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.llm import suggestion_generator


class TestIsEnabled:
    def test_disabled_by_default(self, monkeypatch):
        monkeypatch.delenv("LLM_SUGGESTIONS_ENABLED", raising=False)
        assert suggestion_generator.is_enabled() is False

    def test_enabled_when_true(self, monkeypatch):
        monkeypatch.setenv("LLM_SUGGESTIONS_ENABLED", "true")
        assert suggestion_generator.is_enabled() is True

    def test_disabled_when_false(self, monkeypatch):
        monkeypatch.setenv("LLM_SUGGESTIONS_ENABLED", "false")
        assert suggestion_generator.is_enabled() is False

    def test_case_insensitive(self, monkeypatch):
        monkeypatch.setenv("LLM_SUGGESTIONS_ENABLED", "TRUE")
        assert suggestion_generator.is_enabled() is True


@pytest.mark.anyio
class TestGenerateSuggestion:
    @pytest.fixture
    def anyio_backend(self):
        return "asyncio"

    async def test_returns_none_when_feature_disabled(self, monkeypatch):
        monkeypatch.setenv("LLM_SUGGESTIONS_ENABLED", "false")
        result = await suggestion_generator.generate_suggestion(
            category="SQL_INJECTION", cwe_id="CWE-89",
            evidence_snippet="query + userInput", style_example=None,
        )
        assert result is None

    async def test_returns_none_when_no_api_key(self, monkeypatch):
        monkeypatch.setenv("LLM_SUGGESTIONS_ENABLED", "true")
        monkeypatch.delenv("LLM_API_KEY", raising=False)
        result = await suggestion_generator.generate_suggestion(
            category="SQL_INJECTION", cwe_id="CWE-89",
            evidence_snippet="query + userInput", style_example=None,
        )
        assert result is None

    async def test_returns_text_on_success(self, monkeypatch):
        monkeypatch.setenv("LLM_SUGGESTIONS_ENABLED", "true")
        monkeypatch.setenv("LLM_API_KEY", "sk-test-key")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "content": [{"type": "text", "text": "Usa PreparedStatement en vez de concatenar el SQL."}]
        }
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = False

        with patch("app.llm.suggestion_generator.httpx.AsyncClient", return_value=mock_client):
            result = await suggestion_generator.generate_suggestion(
                category="SQL_INJECTION", cwe_id="CWE-89",
                evidence_snippet='query = "SELECT * FROM users WHERE id=" + id',
                style_example="Evita SELECT *; especifica las columnas.",
            )

        assert result == "Usa PreparedStatement en vez de concatenar el SQL."
        # The API key must never be logged/exposed -- only sent as a header.
        _, kwargs = mock_client.post.call_args
        assert kwargs["headers"]["x-api-key"] == "sk-test-key"
        assert "SQL_INJECTION" in kwargs["json"]["messages"][0]["content"]

    async def test_returns_none_on_non_200_response(self, monkeypatch):
        monkeypatch.setenv("LLM_SUGGESTIONS_ENABLED", "true")
        monkeypatch.setenv("LLM_API_KEY", "sk-test-key")

        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = False

        with patch("app.llm.suggestion_generator.httpx.AsyncClient", return_value=mock_client):
            result = await suggestion_generator.generate_suggestion(
                category="XSS", cwe_id=None, evidence_snippet="innerHTML = userInput", style_example=None,
            )
        assert result is None

    async def test_returns_none_on_timeout(self, monkeypatch):
        monkeypatch.setenv("LLM_SUGGESTIONS_ENABLED", "true")
        monkeypatch.setenv("LLM_API_KEY", "sk-test-key")

        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.TimeoutException("timed out")
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = False

        with patch("app.llm.suggestion_generator.httpx.AsyncClient", return_value=mock_client):
            result = await suggestion_generator.generate_suggestion(
                category="XSS", cwe_id=None, evidence_snippet="innerHTML = userInput", style_example=None,
            )
        assert result is None

    async def test_returns_none_on_malformed_response_body(self, monkeypatch):
        monkeypatch.setenv("LLM_SUGGESTIONS_ENABLED", "true")
        monkeypatch.setenv("LLM_API_KEY", "sk-test-key")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.side_effect = ValueError("not json")
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = False

        with patch("app.llm.suggestion_generator.httpx.AsyncClient", return_value=mock_client):
            result = await suggestion_generator.generate_suggestion(
                category="XSS", cwe_id=None, evidence_snippet="innerHTML = userInput", style_example=None,
            )
        assert result is None

    async def test_returns_none_on_blank_response_text(self, monkeypatch):
        monkeypatch.setenv("LLM_SUGGESTIONS_ENABLED", "true")
        monkeypatch.setenv("LLM_API_KEY", "sk-test-key")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"content": [{"type": "text", "text": "   "}]}
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = False

        with patch("app.llm.suggestion_generator.httpx.AsyncClient", return_value=mock_client):
            result = await suggestion_generator.generate_suggestion(
                category="XSS", cwe_id=None, evidence_snippet="x", style_example=None,
            )
        assert result is None
