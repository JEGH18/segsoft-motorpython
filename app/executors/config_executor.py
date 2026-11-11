import os

import yaml

from app.executors.base import RuleExecutor
from app.executors.limits import Deadline, compile_pattern, search

# Extensiones que realmente pueden ser un archivo de configuración. Sin este
# filtro, execute() trataba CUALQUIER archivo del repo (un .java, un .jsx, un
# pom.xml) como si pudiera contener las claves buscadas -- y como ninguno de
# esos archivos las define nunca, un check "must_exist" terminaba disparando
# un hallazgo en cada archivo del repositorio que no fuera el de config real,
# en vez de solo avisar cuando la clave de verdad falta.
_CONFIG_EXTENSIONS = {".yml", ".yaml", ".properties", ".env", ".toml", ".ini", ".cfg", ".conf"}


class ConfigExecutor(RuleExecutor):
    """
    Checks configuration files (YAML, .properties, .env) against rules.
    Payload schema:
      {
        "checks": [
          {"key": "DEBUG", "not_value": "true"},
          {"key": "SECRET_KEY", "must_exist": true},
          {"key": "ALLOWED_HOSTS", "pattern": "\\*"}
        ]
      }
    A key matches either the full dotted path of a value ("spring.jpa.show-sql") or, for nested
    YAML, its trailing segments ("show-sql", "jpa.show-sql"). Every matching value is checked, so
    two settings that share a last segment ("app.password" and "spring.datasource.password") no
    longer hide each other.
    """

    def execute(self, payload: dict, artifact_path: str) -> list:
        checks = payload.get("checks", [])
        if not checks:
            return []

        ext = os.path.splitext(artifact_path)[1].lower()
        if ext not in _CONFIG_EXTENSIONS:
            return []
        try:
            config = self._load_config(artifact_path, ext)
        except Exception:
            return []

        deadline = Deadline()
        findings = []
        for check in checks:
            key = check.get("key", "")
            values = self._values_for(config, key)

            if check.get("must_exist") and not values:
                findings.append({
                    "filePath": artifact_path,
                    "lineNumber": None,
                    "evidenceSnippet": f"Required key '{key}' not found",
                })

            for full_key, value in values:
                if "not_value" in check and str(value).lower() == str(check["not_value"]).lower():
                    findings.append({
                        "filePath": artifact_path,
                        "lineNumber": None,
                        "evidenceSnippet": f"{full_key}={value}",
                    })

                if "pattern" in check and value is not None:
                    if search(compile_pattern(check["pattern"]), str(value), deadline):
                        findings.append({
                            "filePath": artifact_path,
                            "lineNumber": None,
                            "evidenceSnippet": f"{full_key}={value}",
                        })

        return findings

    @staticmethod
    def _values_for(config: dict, key: str) -> list[tuple[str, object]]:
        if not key:
            return []
        if key in config:
            return [(key, config[key])]
        suffix = "." + key
        return [(full_key, value) for full_key, value in config.items() if full_key.endswith(suffix)]

    def _load_config(self, path: str, ext: str) -> dict:
        if ext in (".yml", ".yaml"):
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                data = yaml.safe_load(fh) or {}
            return self._flatten(data) if isinstance(data, dict) else {}

        result = {}
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, _, v = line.partition("=")
                    result[k.strip()] = v.strip().strip('"').strip("'")
        return result

    def _flatten(self, d: dict, prefix: str = "") -> dict:
        result = {}
        for k, v in d.items():
            full_key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, dict):
                result.update(self._flatten(v, full_key))
            else:
                result[full_key] = v
        return result
