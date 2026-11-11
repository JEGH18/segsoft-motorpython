import os
import tempfile
import pytest
from app.executors.dependency_executor import DependencyExecutor

executor = DependencyExecutor()

VULNS = [
    {"ecosystem": "maven",  "group": "com.example", "artifact": "vuln-lib", "below_version": "2.0.0", "cve": "CVE-2024-0001"},
    {"ecosystem": "npm",    "package": "lodash",     "below_version": "4.17.21", "cve": "CVE-2021-23337"},
    {"ecosystem": "pypi",   "package": "requests",   "below_version": "2.28.2",  "cve": "CVE-2023-32681"},
]


def _file(content: str, name: str) -> str:
    d = tempfile.mkdtemp()
    path = os.path.join(d, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


def test_detects_vulnerable_npm_package():
    content = '{"dependencies":{"lodash":"^4.17.0"}}\n'
    path = _file(content, "package.json")
    try:
        findings = executor.execute({"known_vulnerable": VULNS}, path)
        assert len(findings) == 1
        assert "CVE-2021-23337" in findings[0]["evidenceSnippet"]
    finally:
        import shutil; shutil.rmtree(os.path.dirname(path))


def test_safe_npm_package_no_findings():
    content = '{"dependencies":{"lodash":"^4.17.21"}}\n'
    path = _file(content, "package.json")
    try:
        findings = executor.execute({"known_vulnerable": VULNS}, path)
        assert findings == []
    finally:
        import shutil; shutil.rmtree(os.path.dirname(path))


def test_detects_vulnerable_pypi_package():
    content = "requests==2.20.0\nflask==2.3.2\n"
    path = _file(content, "requirements.txt")
    try:
        findings = executor.execute({"known_vulnerable": VULNS}, path)
        assert len(findings) == 1
        assert "CVE-2023-32681" in findings[0]["evidenceSnippet"]
    finally:
        import shutil; shutil.rmtree(os.path.dirname(path))


def test_detects_vulnerable_maven_dependency():
    content = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>vuln-lib</artifactId>
      <version>1.5.0</version>
    </dependency>
  </dependencies>
</project>"""
    path = _file(content, "pom.xml")
    try:
        findings = executor.execute({"known_vulnerable": VULNS}, path)
        assert len(findings) == 1
        assert "CVE-2024-0001" in findings[0]["evidenceSnippet"]
    finally:
        import shutil; shutil.rmtree(os.path.dirname(path))


def test_empty_known_vulnerable_list_returns_empty():
    content = '{"dependencies":{"lodash":"4.17.0"}}\n'
    path = _file(content, "package.json")
    try:
        findings = executor.execute({"known_vulnerable": []}, path)
        assert findings == []
    finally:
        import shutil; shutil.rmtree(os.path.dirname(path))


def test_maven_version_from_property_is_resolved(tmp_path):
    pom = tmp_path / "pom.xml"
    pom.write_text(
        '<project xmlns="http://maven.apache.org/POM/4.0.0">'
        "<properties><struts.version>2.5.10</struts.version></properties>"
        "<dependencies><dependency><groupId>org.apache.struts</groupId>"
        "<artifactId>struts2-core</artifactId><version>${struts.version}</version>"
        "</dependency></dependencies></project>",
        encoding="utf-8",
    )
    from app.executors.dependency_executor import DependencyExecutor

    findings = DependencyExecutor().execute(
        {"known_vulnerable": [{"ecosystem": "maven", "group": "org.apache.struts",
                               "artifact": "struts2-core", "below_version": "2.5.33",
                               "cve": "CVE-2021-31805"}]},
        str(pom),
    )
    assert len(findings) == 1
    assert "2.5.10" in findings[0]["evidenceSnippet"]
