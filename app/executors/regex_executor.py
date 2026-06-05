import re
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError

from app.executors.base import RuleExecutor
from app.executors.errors import ControlledRuleError

_TIMEOUT_SECONDS = 5


class RegexExecutor(RuleExecutor):

    def execute(self, payload: dict, artifact_path: str) -> list:
        pattern_str: str = payload.get("pattern", "")
        if not pattern_str:
            return []

        try:
            pattern = re.compile(pattern_str)
        except re.error as exc:
            raise ControlledRuleError("INVALID_REGEX", f"Regex inválida: {exc}") from exc

        findings = []

        def scan_file(path: str) -> list:
            results = []
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line_number, line in enumerate(fh, start=1):
                    for match in pattern.finditer(line):
                        results.append({
                            "filePath": path,
                            "lineNumber": line_number,
                            "evidenceSnippet": line.rstrip("\n"),
                            "matchStart": match.start(),
                            "matchEnd": match.end(),
                        })
            return results

        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(scan_file, artifact_path)
            try:
                findings = future.result(timeout=_TIMEOUT_SECONDS)
            except FuturesTimeoutError:
                future.cancel()
                raise ControlledRuleError("RULE_TIMEOUT", "La ejecución de la regla superó el timeout permitido")
            except FileNotFoundError as exc:
                raise ControlledRuleError("FILE_NOT_FOUND", f"Archivo no encontrado: {artifact_path}") from exc
            except OSError as exc:
                raise ControlledRuleError("FILE_IO_ERROR", f"Error leyendo artefacto: {exc}") from exc

        return findings
