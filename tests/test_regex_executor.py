import pytest

from app.executors.errors import ControlledRuleError
from app.executors.regex_executor import RegexExecutor


def test_regex_executor_returns_matches(tmp_path):
    artifact = tmp_path / "sample.py"
    artifact.write_text("password = abc123\nclean = true\n", encoding="utf-8")

    executor = RegexExecutor()
    findings = executor.execute({"pattern": r"password\s*="}, str(artifact))

    assert len(findings) == 1
    assert findings[0]["lineNumber"] == 1
    assert "password = abc123" in findings[0]["evidenceSnippet"]


def test_regex_executor_no_matches_returns_empty(tmp_path):
    artifact = tmp_path / "clean.py"
    artifact.write_text("hello = 'world'\n", encoding="utf-8")

    executor = RegexExecutor()
    findings = executor.execute({"pattern": r"password\s*="}, str(artifact))

    assert findings == []


def test_regex_executor_nonexistent_file_raises_controlled_error():
    executor = RegexExecutor()

    with pytest.raises(ControlledRuleError) as exc:
        executor.execute({"pattern": r"password\s*="}, "/tmp/does-not-exist.file")

    assert exc.value.error_type == "FILE_NOT_FOUND"
