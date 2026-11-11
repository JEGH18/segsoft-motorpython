import os
import re
from xml.etree import ElementTree

from app.executors.base import RuleExecutor


class DependencyExecutor(RuleExecutor):
    """
    Checks dependency manifests for known-vulnerable packages.
    Payload schema:
      {
        "known_vulnerable": [
          {"ecosystem": "maven",  "group": "org.apache.struts", "artifact": "struts2-core", "below_version": "2.5.33", "cve": "CVE-2021-31805"},
          {"ecosystem": "npm",    "package": "lodash",          "below_version": "4.17.21",  "cve": "CVE-2021-23337"},
          {"ecosystem": "pypi",   "package": "requests",        "below_version": "2.28.2",   "cve": "CVE-2023-32681"}
        ]
      }
    Supports pom.xml, package.json, requirements.txt.
    """

    def execute(self, payload: dict, artifact_path: str) -> list:
        vulns = payload.get("known_vulnerable", [])
        if not vulns:
            return []

        filename = os.path.basename(artifact_path).lower()
        try:
            if filename == "pom.xml":
                return self._check_maven(vulns, artifact_path)
            elif filename == "package.json":
                return self._check_npm(vulns, artifact_path)
            elif filename in ("requirements.txt", "requirements-dev.txt"):
                return self._check_pypi(vulns, artifact_path)
        except Exception:
            pass
        return []

    _POM_NS = "{http://maven.apache.org/POM/4.0.0}"
    _PROPERTY_REF = re.compile(r"\$\{([^}]+)\}")

    def _maven_properties(self, root) -> dict:
        """<properties> of the pom plus project.version / project.parent.version."""
        ns = self._POM_NS
        props = {}
        properties = root.find(f"{ns}properties")
        if properties is not None:
            for prop in properties:
                if isinstance(prop.tag, str) and prop.tag.startswith(ns):
                    props[prop.tag[len(ns):]] = (prop.text or "").strip()
        parent_version = (root.findtext(f"{ns}parent/{ns}version") or "").strip()
        project_version = (root.findtext(f"{ns}version") or "").strip() or parent_version
        if project_version:
            props.setdefault("project.version", project_version)
            props.setdefault("pom.version", project_version)
        if parent_version:
            props.setdefault("project.parent.version", parent_version)
        return props

    def _resolve_maven_version(self, version: str, props: dict) -> str:
        # A few rounds cover properties defined in terms of other properties.
        for _ in range(5):
            if "${" not in version:
                break
            version = self._PROPERTY_REF.sub(lambda m: props.get(m.group(1), m.group(0)), version)
        return "" if "${" in version else version

    def _check_maven(self, vulns: list, path: str) -> list:
        findings = []
        try:
            tree = ElementTree.parse(path)
            root = tree.getroot()
            props = self._maven_properties(root)

            for dep in root.iter("{http://maven.apache.org/POM/4.0.0}dependency"):
                group = (dep.findtext("{http://maven.apache.org/POM/4.0.0}groupId") or "").strip()
                artifact = (dep.findtext("{http://maven.apache.org/POM/4.0.0}artifactId") or "").strip()
                version = self._resolve_maven_version(
                    (dep.findtext("{http://maven.apache.org/POM/4.0.0}version") or "").strip(), props)

                for vuln in vulns:
                    if vuln.get("ecosystem") != "maven":
                        continue
                    if vuln.get("group") == group and vuln.get("artifact") == artifact:
                        if version and self._is_below(version, vuln.get("below_version", "")):
                            findings.append({
                                "filePath": path,
                                "lineNumber": None,
                                "evidenceSnippet": f"{group}:{artifact}:{version} — {vuln.get('cve', 'CVE desconocido')}",
                            })
        except ElementTree.ParseError:
            pass
        return findings

    def _check_npm(self, vulns: list, path: str) -> list:
        import json
        findings = []
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            all_deps = {}
            all_deps.update(data.get("dependencies", {}))
            all_deps.update(data.get("devDependencies", {}))

            for pkg, ver_spec in all_deps.items():
                version = ver_spec.lstrip("^~>=<")
                for vuln in vulns:
                    if vuln.get("ecosystem") != "npm":
                        continue
                    if vuln.get("package") == pkg:
                        if self._is_below(version, vuln.get("below_version", "")):
                            findings.append({
                                "filePath": path,
                                "lineNumber": None,
                                "evidenceSnippet": f"{pkg}@{version} — {vuln.get('cve', 'CVE desconocido')}",
                            })
        except (json.JSONDecodeError, OSError):
            pass
        return findings

    def _check_pypi(self, vulns: list, path: str) -> list:
        findings = []
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    match = re.match(r"([A-Za-z0-9_\-\.]+)\s*([><=!]+)\s*([\d\.]+)?", line)
                    if not match:
                        continue
                    pkg = match.group(1).lower()
                    version = match.group(3) or ""
                    for vuln in vulns:
                        if vuln.get("ecosystem") != "pypi":
                            continue
                        if vuln.get("package", "").lower() == pkg:
                            if self._is_below(version, vuln.get("below_version", "")):
                                findings.append({
                                    "filePath": path,
                                    "lineNumber": None,
                                    "evidenceSnippet": f"{pkg}=={version} — {vuln.get('cve', 'CVE desconocido')}",
                                })
        except OSError:
            pass
        return findings

    @staticmethod
    def _is_below(version: str, threshold: str) -> bool:
        if not version or not threshold:
            return False
        try:
            v = tuple(int(x) for x in re.split(r"[.\-]", version) if x.isdigit())
            t = tuple(int(x) for x in re.split(r"[.\-]", threshold) if x.isdigit())
            return v < t
        except (ValueError, TypeError):
            return False
