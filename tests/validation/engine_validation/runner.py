"""Ejecuta el motor sobre cada fixture.

Usa cada regla ACTIVA real (tests/fixtures/rules_snapshot.json, snapshot de
la base de datos tomado después de V29/V30), es decir, el conjunto completo de
políticas, y la ejecuta contra cada archivo del fixture a través del mismo
endpoint HTTP que usa el backend Spring en producción (/internal/execute-rule).
"""

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .discovery import Fixture, load_expected, source_files
from .matching import Finding, MatchResult, match_findings

# Tipos de regla que el motor sabe ejecutar hoy contra archivos de código o
# manifiestos (AST_QUERY no tiene ninguna regla activa en el snapshot).
EXECUTABLE_TYPES = {"PATTERN_REGEX", "CONFIG_CHECK", "DEPENDENCY_CHECK"}


@dataclass
class FixtureResult:
    fixture: Fixture
    files_analyzed: int
    actual: list[Finding]
    expected: Optional[list[Finding]] = None   # None en los repositorios reales
    match: Optional[MatchResult] = None


@dataclass
class SuiteRun:
    rules_count: int
    results: list[FixtureResult]
    duration_ms: int

    def result_for(self, fixture_id: str) -> FixtureResult:
        return next(r for r in self.results if r.fixture.id == fixture_id)

    @property
    def ground_truth_results(self) -> list[FixtureResult]:
        return [r for r in self.results if r.match is not None]


def load_rules(snapshot_path: Path) -> list[dict]:
    rules = json.loads(snapshot_path.read_text(encoding="utf-8"))
    return sorted((r for r in rules if r["type"] in EXECUTABLE_TYPES), key=lambda r: r["id"])


def run_engine(client, headers: dict, rules: list[dict], fixture: Fixture) -> tuple[int, list[Finding]]:
    files = source_files(fixture)
    findings = []
    for file_path in files:
        rel_path = file_path.relative_to(fixture.path).as_posix()
        for rule in rules:
            response = client.post(
                "/internal/execute-rule",
                headers=headers,
                json={
                    "ruleId": rule["id"],
                    "type": rule["type"],
                    "payload": rule["payload"],
                    "artifactPath": str(file_path),
                    "policyId": "validation-fixture",
                    "category": rule["category"],
                    "severity": rule["severity"],
                    "cweId": rule.get("cweId"),
                },
            )
            if response.status_code != 200:
                raise RuntimeError(
                    f"/internal/execute-rule falló para la regla {rule['id']} sobre {fixture.id}/{rel_path}: "
                    f"{response.status_code} {response.text}"
                )
            body = response.json()
            if body["errors"]:
                raise RuntimeError(f"La regla {rule['id']} sobre {fixture.id}/{rel_path} produjo errores: {body['errors']}")
            for finding in body["findings"]:
                findings.append(Finding(
                    file=rel_path,
                    line=finding["lineNumber"],
                    category=finding["category"],
                    severity=finding["severity"],
                    rule_id=finding["ruleId"],
                ))
    return len(files), sorted(findings, key=Finding.sort_key)


def run_suite(client, headers: dict, fixtures: list[Fixture], snapshot_path: Path) -> SuiteRun:
    started = time.monotonic()
    rules = load_rules(snapshot_path)
    results = []
    for fixture in fixtures:
        files_analyzed, actual = run_engine(client, headers, rules, fixture)
        result = FixtureResult(fixture=fixture, files_analyzed=files_analyzed, actual=actual)
        if fixture.has_ground_truth:
            result.expected = load_expected(fixture)
            result.match = match_findings(result.expected, actual)
        results.append(result)
    return SuiteRun(
        rules_count=len(rules),
        results=results,
        duration_ms=round((time.monotonic() - started) * 1000),
    )
