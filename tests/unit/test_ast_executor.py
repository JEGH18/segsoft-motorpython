import os
import tempfile
import pytest
from app.executors.ast_executor import AstExecutor

executor = AstExecutor()


def _file(content: str, suffix: str = ".py") -> str:
    f = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False)
    f.write(content)
    f.close()
    return f.name


def test_detects_sql_concatenation_in_python():
    code = (
        'def get_user(name):\n'
        '    query = "SELECT * FROM users WHERE name = " + name\n'
        '    return db.execute(query)\n'
    )
    path = _file(code)
    try:
        findings = executor.execute({"check_type": "sql_concatenation"}, path)
        assert len(findings) >= 1
        assert any("query" in f["evidenceSnippet"].lower() or "select" in f["evidenceSnippet"].lower()
                   for f in findings)
    finally:
        os.unlink(path)


def test_detects_exec_call_in_python():
    code = 'exec("import os; os.system(user_input)")\n'
    path = _file(code)
    try:
        findings = executor.execute({"check_type": "exec_call"}, path)
        assert len(findings) == 1
        assert findings[0]["lineNumber"] == 1
    finally:
        os.unlink(path)


def test_safe_python_returns_no_findings():
    code = (
        'def safe_query(conn, user_id):\n'
        '    return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))\n'
    )
    path = _file(code)
    try:
        findings = executor.execute({"check_type": "sql_concatenation"}, path)
        assert findings == []
    finally:
        os.unlink(path)


def test_detects_sql_concatenation_in_java():
    code = 'String query = "SELECT * FROM users WHERE name = " + userName;\n'
    path = _file(code, suffix=".java")
    try:
        findings = executor.execute({"check_type": "sql_concatenation"}, path)
        assert len(findings) >= 1
    finally:
        os.unlink(path)


def test_empty_check_type_returns_empty():
    path = _file("x = 1\n")
    try:
        findings = executor.execute({}, path)
        assert findings == []
    finally:
        os.unlink(path)
