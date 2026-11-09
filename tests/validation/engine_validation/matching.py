"""Emparejamiento de hallazgos obtenidos contra esperados.

Un hallazgo coincide con uno esperado si comparte archivo, categoría y línea
(line es None en las reglas CONFIG_CHECK y DEPENDENCY_CHECK, que revisan el
archivo completo). La comparación es por multiconjunto: cada esperado se
empareja como máximo una vez, así que dos hallazgos iguales en la misma línea
necesitan dos esperados.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class Finding:
    file: str
    line: Optional[int]
    category: str
    severity: str
    rule_id: Optional[str] = None

    def match_key(self) -> tuple:
        return (self.file, self.category, self.line)

    def sort_key(self) -> tuple:
        return (
            self.file,
            -1 if self.line is None else self.line,
            self.category,
            self.severity,
            self.rule_id or "",
        )

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "line": self.line,
            "category": self.category,
            "severity": self.severity,
            "ruleId": self.rule_id,
        }

    def describe(self) -> str:
        line = "sin línea" if self.line is None else f"línea {self.line}"
        return f"{self.file} ({line}) {self.category} {self.severity} regla {self.rule_id or '?'}"


@dataclass
class MatchResult:
    true_positives: list[tuple[Finding, Finding]] = field(default_factory=list)  # (esperado, obtenido)
    false_positives: list[Finding] = field(default_factory=list)
    false_negatives: list[Finding] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.false_positives and not self.false_negatives


def match_findings(expected: list[Finding], actual: list[Finding]) -> MatchResult:
    remaining: dict[tuple, list[Finding]] = defaultdict(list)
    for finding in sorted(actual, key=Finding.sort_key):
        remaining[finding.match_key()].append(finding)

    result = MatchResult()
    for wanted in sorted(expected, key=Finding.sort_key):
        candidates = remaining[wanted.match_key()]
        if not candidates:
            result.false_negatives.append(wanted)
            continue
        result.true_positives.append((wanted, candidates.pop(_best_candidate(wanted, candidates))))

    result.false_positives = sorted(
        (finding for group in remaining.values() for finding in group),
        key=Finding.sort_key,
    )
    return result


def _best_candidate(wanted: Finding, candidates: list[Finding]) -> int:
    """La severidad y la regla no deciden si hay coincidencia, pero entre
    varios candidatos con la misma clave se prefiere el de la misma regla y
    luego el de la misma severidad, para que el detalle del reporte empareje
    los hallazgos que realmente se corresponden."""
    for i, candidate in enumerate(candidates):
        if wanted.rule_id and candidate.rule_id == wanted.rule_id:
            return i
    for i, candidate in enumerate(candidates):
        if candidate.severity == wanted.severity:
            return i
    return 0
