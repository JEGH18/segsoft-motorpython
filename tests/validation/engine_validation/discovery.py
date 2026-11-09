"""Descubre los fixtures del dataset de referencia sin configuración manual.

    tests/fixtures/reference-repos/
        vulnerable/<repo>/expected.json   vulnerabilidades plantadas (ground truth)
        secure/<repo>/expected.json       sin hallazgos esperados: mide falsos positivos
        real/<repo>/                      repositorios reales de PDG ICESI, sin ground
                                          truth: solo análisis cualitativo, fuera de
                                          las métricas

Agregar un fixture es crear su carpeta en el tipo que corresponda; la suite no
necesita cambios.
"""

import json
from dataclasses import dataclass
from pathlib import Path

from .matching import Finding

KINDS = ("vulnerable", "secure", "real")
EXPECTED_FILE = "expected.json"
_IGNORED_NAMES = {EXPECTED_FILE, ".DS_Store"}


@dataclass(frozen=True)
class Fixture:
    name: str
    kind: str
    path: Path

    @property
    def id(self) -> str:
        return f"{self.kind}/{self.name}"

    @property
    def has_ground_truth(self) -> bool:
        return self.kind != "real"


def discover_fixtures(root: Path) -> list[Fixture]:
    fixtures = []
    for kind in KINDS:
        kind_dir = root / kind
        if not kind_dir.is_dir():
            continue
        for repo_dir in sorted(p for p in kind_dir.iterdir() if p.is_dir()):
            fixtures.append(Fixture(name=repo_dir.name, kind=kind, path=repo_dir))
    return fixtures


def source_files(fixture: Fixture) -> list[Path]:
    """Archivos que analiza el motor. Se excluye la carpeta .git de los
    repositorios reales, pero no los demás archivos ocultos: un .env es
    justamente lo que el motor debe revisar."""
    return sorted(
        p for p in fixture.path.rglob("*")
        if p.is_file()
        and p.name not in _IGNORED_NAMES
        and ".git" not in p.relative_to(fixture.path).parts
    )


def load_expected(fixture: Fixture) -> list[Finding]:
    expected_path = fixture.path / EXPECTED_FILE
    if not expected_path.exists():
        raise FileNotFoundError(f"{fixture.id} no tiene {EXPECTED_FILE}")
    data = json.loads(expected_path.read_text(encoding="utf-8"))
    findings = [
        Finding(
            file=item["file"],
            line=item.get("line"),
            category=item["category"],
            severity=item["severity"],
            rule_id=item.get("ruleId"),
        )
        for item in data.get("findings") or []
    ]
    if fixture.kind == "secure" and findings:
        raise ValueError(f"{fixture.id} es un fixture seguro y no puede tener hallazgos esperados")
    return sorted(findings, key=Finding.sort_key)
