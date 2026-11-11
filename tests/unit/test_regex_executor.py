import os
import tempfile
import time

import pytest

from app.executors.errors import ControlledRuleError
from app.executors.regex_executor import RegexExecutor

executor = RegexExecutor()


def _file(content: str, suffix: str = ".java") -> str:
    f = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False)
    f.write(content)
    f.close()
    return f.name


def test_matches_simple_pattern():
    path = _file('String apiKey = "abc123";\n')
    try:
        findings = executor.execute({"pattern": r"(?i)api[_-]?key"}, path)
        assert len(findings) == 1
        assert findings[0]["lineNumber"] == 1
        assert "apiKey" in findings[0]["evidenceSnippet"]
    finally:
        os.unlink(path)


def test_no_match_returns_empty():
    path = _file("public class Safe {}\n")
    try:
        findings = executor.execute({"pattern": r"password\s*="}, path)
        assert findings == []
    finally:
        os.unlink(path)


def test_multiple_matches_on_different_lines():
    content = "api_key=abc\npassword=secret\ntoken=xyz\n"
    path = _file(content, suffix=".env")
    try:
        findings = executor.execute({"pattern": r"(api_key|password|token)\s*="}, path)
        assert len(findings) == 3
    finally:
        os.unlink(path)


def test_invalid_pattern_raises_controlled_error():
    path = _file("any content\n")
    try:
        with pytest.raises(ControlledRuleError) as exc:
            executor.execute({"pattern": "[invalid("}, path)
        assert exc.value.error_type == "INVALID_REGEX"
    finally:
        os.unlink(path)


def test_empty_pattern_returns_empty():
    path = _file("some content\n")
    try:
        findings = executor.execute({"pattern": ""}, path)
        assert findings == []
    finally:
        os.unlink(path)


def test_redos_pattern_is_stopped_by_the_timeout(monkeypatch):
    """Catastrophic backtracking must end in RULE_TIMEOUT close to the limit, not hang.

    With the stdlib re module this pattern ran for minutes: re holds the GIL, so the old
    thread-based timeout never fired."""
    monkeypatch.setattr("app.executors.limits.RULE_TIMEOUT_SECONDS", 0.5)
    path = _file("a" * 60 + "b\n")
    try:
        started = time.monotonic()
        with pytest.raises(ControlledRuleError) as exc:
            executor.execute({"pattern": r"^(a|aa)+$"}, path)
        assert exc.value.error_type == "RULE_TIMEOUT"
        assert time.monotonic() - started < 3
    finally:
        os.unlink(path)


def test_missing_pattern_key_returns_empty():
    path = _file("content\n")
    try:
        findings = executor.execute({}, path)
        assert findings == []
    finally:
        os.unlink(path)
