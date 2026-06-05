import os

import yaml

from app.executors.base import RuleExecutor


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
    """

    _CONFIG_EXTENSIONS = {
        ".yml", ".yaml", ".properties", ".env", ".ini", ".cfg", ".conf", ".toml",
    }

    def execute(self, payload: dict, artifact_path: str) -> list:
        checks = payload.get("checks", [])
        if not checks:
            return []

        ext = os.path.splitext(artifact_path)[1].lower()
        if ext not in self._CONFIG_EXTENSIONS:
            return []
        try:
            config = self._load_config(artifact_path, ext)
        except Exception:
            return []

        findings = []
        for check in checks:
            key = check.get("key", "")
            value = config.get(key)

            if check.get("must_exist") and value is None:
                findings.append({
                    "filePath": artifact_path,
                    "lineNumber": None,
                    "evidenceSnippet": f"Required key '{key}' not found",
                })

            if "not_value" in check and str(value).lower() == str(check["not_value"]).lower():
                findings.append({
                    "filePath": artifact_path,
                    "lineNumber": None,
                    "evidenceSnippet": f"{key}={value}",
                })

            if "pattern" in check and value is not None:
                import re
                if re.search(check["pattern"], str(value)):
                    findings.append({
                        "filePath": artifact_path,
                        "lineNumber": None,
                        "evidenceSnippet": f"{key}={value}",
                    })

        return findings

    def _load_config(self, path: str, ext: str) -> dict:
        if ext in (".yml", ".yaml"):
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                data = yaml.safe_load(fh) or {}
            return self._flatten(data)

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
            full_key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, dict):
                result.update(self._flatten(v, full_key))
            else:
                result[full_key] = v
                result[k] = v  # also index by last segment
        return result
