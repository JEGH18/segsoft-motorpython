import os
import tempfile
import pytest
from app.executors.config_executor import ConfigExecutor

executor = ConfigExecutor()


def _file(content: str, suffix: str = ".properties") -> str:
    f = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False)
    f.write(content)
    f.close()
    return f.name


def test_detects_debug_true_in_properties():
    path = _file("DEBUG=true\nSECRET_KEY=s3cr3t\n")
    try:
        findings = executor.execute(
            {"checks": [{"key": "DEBUG", "not_value": "true"}]}, path
        )
        assert len(findings) == 1
        assert "DEBUG" in findings[0]["evidenceSnippet"]
    finally:
        os.unlink(path)


def test_no_findings_for_safe_properties():
    path = _file("DEBUG=false\nLOG_LEVEL=INFO\n")
    try:
        findings = executor.execute(
            {"checks": [{"key": "DEBUG", "not_value": "true"}]}, path
        )
        assert findings == []
    finally:
        os.unlink(path)


def test_detects_missing_required_key():
    path = _file("LOG_LEVEL=INFO\n")
    try:
        findings = executor.execute(
            {"checks": [{"key": "SECRET_KEY", "must_exist": True}]}, path
        )
        assert len(findings) == 1
        assert "SECRET_KEY" in findings[0]["evidenceSnippet"]
    finally:
        os.unlink(path)


def test_detects_pattern_in_value():
    path = _file("ALLOWED_HOSTS=*\n")
    try:
        findings = executor.execute(
            {"checks": [{"key": "ALLOWED_HOSTS", "pattern": r"\*"}]}, path
        )
        assert len(findings) == 1
    finally:
        os.unlink(path)


def test_yaml_config_detects_debug_true():
    content = "spring:\n  jpa:\n    show-sql: true\ndebug: true\n"
    path = _file(content, suffix=".yml")
    try:
        findings = executor.execute(
            {"checks": [{"key": "debug", "not_value": "true"}]}, path
        )
        assert len(findings) >= 1
    finally:
        os.unlink(path)


def test_env_file_with_quoted_values():
    path = _file('API_KEY="my-key"\nDEBUG="true"\n', suffix=".env")
    try:
        findings = executor.execute(
            {"checks": [{"key": "DEBUG", "not_value": "true"}]}, path
        )
        assert len(findings) == 1
    finally:
        os.unlink(path)
