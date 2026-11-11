from app.executors.base import RuleExecutor
from app.executors.errors import ControlledRuleError
from app.executors.limits import Deadline, compile_pattern, finditer


class RegexExecutor(RuleExecutor):

    def execute(self, payload: dict, artifact_path: str) -> list:
        pattern_str: str = payload.get("pattern", "")
        if not pattern_str:
            return []

        pattern = compile_pattern(pattern_str)
        deadline = Deadline()

        findings = []
        try:
            with open(artifact_path, "r", encoding="utf-8", errors="replace") as fh:
                for line_number, line in enumerate(fh, start=1):
                    deadline.remaining()
                    for match in finditer(pattern, line, deadline):
                        findings.append({
                            "filePath": artifact_path,
                            "lineNumber": line_number,
                            "evidenceSnippet": line.rstrip("\n"),
                            "matchStart": match.start(),
                            "matchEnd": match.end(),
                        })
        except FileNotFoundError as exc:
            raise ControlledRuleError("FILE_NOT_FOUND", f"Archivo no encontrado: {artifact_path}") from exc
        except OSError as exc:
            raise ControlledRuleError("FILE_IO_ERROR", f"Error leyendo artefacto: {exc}") from exc

        return findings
