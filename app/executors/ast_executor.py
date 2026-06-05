import ast
import os
import re
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError

from app.executors.base import RuleExecutor

_TIMEOUT_SECONDS = 5

_SQL_CONCAT_PATTERNS = [
    re.compile(r'(query|sql)\s*[+]=?\s*["\']', re.IGNORECASE),
    re.compile(r'["\'].*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)[^"\']*["\'].*\+', re.IGNORECASE),
    re.compile(r'\+\s*(query|sql|name|id|user)', re.IGNORECASE),
    re.compile(r'execute\s*\(\s*["\'][^"\']*\+', re.IGNORECASE),
    re.compile(r'Statement\s*\.\s*execute\s*\(\s*"', re.IGNORECASE),
]


class AstExecutor(RuleExecutor):
    """
    Structural analysis executor.
    Payload schema:
      {"check_type": "sql_concatenation" | "exec_call" | "hardcoded_secret"}
    For Python files uses the ast module; for others uses pattern-based heuristics.
    """

    def execute(self, payload: dict, artifact_path: str) -> list:
        check_type = payload.get("check_type", "")
        if not check_type:
            return []

        ext = os.path.splitext(artifact_path)[1].lower()

        def run():
            if ext == ".py":
                return self._check_python(check_type, artifact_path)
            else:
                return self._check_generic(check_type, artifact_path)

        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(run)
            try:
                return future.result(timeout=_TIMEOUT_SECONDS)
            except FuturesTimeoutError:
                future.cancel()
                return []

    def _check_python(self, check_type: str, path: str) -> list:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                source = fh.read()
            tree = ast.parse(source, filename=path)
        except SyntaxError:
            return self._check_generic(check_type, path)

        findings = []
        lines = source.splitlines()

        if check_type == "sql_concatenation":
            for node in ast.walk(tree):
                if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                    line_src = lines[node.lineno - 1] if node.lineno <= len(lines) else ""
                    if any(kw in line_src.lower() for kw in ("sql", "query", "select", "insert", "update", "delete")):
                        findings.append({
                            "filePath": path,
                            "lineNumber": node.lineno,
                            "evidenceSnippet": line_src.strip(),
                        })

        elif check_type == "exec_call":
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func = node.func
                    name = ""
                    if isinstance(func, ast.Name):
                        name = func.id
                    elif isinstance(func, ast.Attribute):
                        name = func.attr
                    if name in ("exec", "eval", "compile", "__import__"):
                        line_src = lines[node.lineno - 1] if node.lineno <= len(lines) else ""
                        findings.append({
                            "filePath": path,
                            "lineNumber": node.lineno,
                            "evidenceSnippet": line_src.strip(),
                        })

        return findings

    def _check_generic(self, check_type: str, path: str) -> list:
        findings = []
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line_number, line in enumerate(fh, start=1):
                    if check_type == "sql_concatenation":
                        for pattern in _SQL_CONCAT_PATTERNS:
                            if pattern.search(line):
                                findings.append({
                                    "filePath": path,
                                    "lineNumber": line_number,
                                    "evidenceSnippet": line.rstrip("\n"),
                                })
                                break
                    elif check_type == "exec_call":
                        if re.search(r'\bRuntime\.exec\b|\bProcessBuilder\b', line):
                            findings.append({
                                "filePath": path,
                                "lineNumber": line_number,
                                "evidenceSnippet": line.rstrip("\n"),
                            })
        except OSError:
            pass
        return findings
