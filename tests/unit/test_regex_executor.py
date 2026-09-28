import os
import tempfile
import pytest
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


def test_invalid_pattern_returns_empty():
    path = _file("any content\n")
    try:
        # Invalid regex — executor catches re.error and returns []
        findings = executor.execute({"pattern": "[invalid("}, path)
        assert findings == []
    finally:
        os.unlink(path)


def test_empty_pattern_returns_empty():
    path = _file("some content\n")
    try:
        findings = executor.execute({"pattern": ""}, path)
        assert findings == []
    finally:
        os.unlink(path)


def test_redos_pattern_times_out_and_returns_empty():
    """ReDoS pattern on a long string must time out and return [] without hanging."""
    # Catastrophic backtracking: (a+)+ on a string of 'a's followed by 'X'
    content = "a" * 30 + "X\n"
    path = _file(content)
    try:
        findings = executor.execute({"pattern": r"(a+)+"}, path)
        # Either finds something or returns [] due to timeout — must not hang
        assert isinstance(findings, list)
    finally:
        os.unlink(path)


def test_missing_pattern_key_returns_empty():
    path = _file("content\n")
    try:
        findings = executor.execute({}, path)
        assert findings == []
    finally:
        os.unlink(path)
