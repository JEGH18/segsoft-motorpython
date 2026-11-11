import ast
import os

from app.executors.base import RuleExecutor
from app.executors.errors import ControlledRuleError
from app.executors.limits import MAX_AST_FILE_BYTES, Deadline, compile_pattern, search

_SQL_CONCAT_PATTERNS = [
    r'(?i)(query|sql)\s*[+]=?\s*["\']',
    r'(?i)["\'].*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)[^"\']*["\'].*\+',
    r'(?i)\+\s*(query|sql|name|id|user)',
    r'(?i)execute\s*\(\s*["\'][^"\']*\+',
    r'(?i)Statement\s*\.\s*execute\s*\(\s*"',
]
_EXEC_CALL_PATTERN = r'\bRuntime\.exec\b|\bProcessBuilder\b'


class AstExecutor(RuleExecutor):
    """
    Structural analysis executor.
    Payload schema:
      {"check_type": "sql_concatenation" | "exec_call" | "hardcoded_secret"}
    For Python files uses the ast module; for others uses pattern-based heuristics.
    Every check is bounded by the rule deadline: running out of time raises RULE_TIMEOUT
    instead of silently returning no findings.
    """

    def execute(self, payload: dict, artifact_path: str) -> list:
        check_type = payload.get("check_type", "")
        if not check_type:
            return []

        deadline = Deadline()
        ext = os.path.splitext(artifact_path)[1].lower()
        try:
            if ext == ".py" and os.path.getsize(artifact_path) <= MAX_AST_FILE_BYTES:
                return self._check_python(check_type, artifact_path, deadline)
            return self._check_generic(check_type, artifact_path, deadline)
        except FileNotFoundError as exc:
            raise ControlledRuleError("FILE_NOT_FOUND", f"Archivo no encontrado: {artifact_path}") from exc
        except OSError as exc:
            raise ControlledRuleError("FILE_IO_ERROR", f"Error leyendo artefacto: {exc}") from exc

    def _check_python(self, check_type: str, path: str, deadline: Deadline) -> list:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            source = fh.read()
        try:
            tree = ast.parse(source, filename=path)
        except (SyntaxError, ValueError, RecursionError):
            return self._check_generic(check_type, path, deadline)

        findings = []
        lines = source.splitlines()

        if check_type == "sql_concatenation":
            for node in ast.walk(tree):
                deadline.remaining()
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
                deadline.remaining()
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

    def _check_generic(self, check_type: str, path: str, deadline: Deadline) -> list:
        if check_type == "sql_concatenation":
            patterns = [compile_pattern(p) for p in _SQL_CONCAT_PATTERNS]
        elif check_type == "exec_call":
            patterns = [compile_pattern(_EXEC_CALL_PATTERN)]
        else:
            return []

        findings = []
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line_number, line in enumerate(fh, start=1):
                for pattern in patterns:
                    if search(pattern, line, deadline):
                        findings.append({
                            "filePath": path,
                            "lineNumber": line_number,
                            "evidenceSnippet": line.rstrip("\n"),
                        })
                        break
        return findings
