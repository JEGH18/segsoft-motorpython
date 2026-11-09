"""Métricas de desempeño del motor, globales y por categoría.

precision = TP / (TP + FP), recall = TP / (TP + FN),
f1Score = 2 * precision * recall / (precision + recall).
Si un denominador es 0, la métrica se reporta como None (null en el JSON) en
lugar de fallar o de inventar un valor.

Los falsos positivos se atribuyen a la categoría del hallazgo obtenido y los
verdaderos positivos y falsos negativos a la del esperado.
"""

from dataclasses import dataclass
from typing import Iterable, Optional

from .matching import MatchResult

DECIMALS = 4


@dataclass(frozen=True)
class Counts:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    def __add__(self, other: "Counts") -> "Counts":
        return Counts(self.tp + other.tp, self.fp + other.fp, self.fn + other.fn)


def counts_of(result: MatchResult) -> Counts:
    return Counts(len(result.true_positives), len(result.false_positives), len(result.false_negatives))


def total_counts(results: Iterable[MatchResult]) -> Counts:
    total = Counts()
    for result in results:
        total += counts_of(result)
    return total


def counts_by_category(results: Iterable[MatchResult], categories: Iterable[str]) -> dict[str, Counts]:
    tp: dict[str, int] = {c: 0 for c in categories}
    fp: dict[str, int] = dict.fromkeys(tp, 0)
    fn: dict[str, int] = dict.fromkeys(tp, 0)
    for result in results:
        for wanted, _ in result.true_positives:
            tp[wanted.category] = tp.get(wanted.category, 0) + 1
        for finding in result.false_positives:
            fp[finding.category] = fp.get(finding.category, 0) + 1
        for finding in result.false_negatives:
            fn[finding.category] = fn.get(finding.category, 0) + 1
    names = sorted(set(tp) | set(fp) | set(fn))
    return {c: Counts(tp.get(c, 0), fp.get(c, 0), fn.get(c, 0)) for c in names}


def compute_metrics(counts: Counts) -> dict:
    precision = _ratio(counts.tp, counts.tp + counts.fp)
    recall = _ratio(counts.tp, counts.tp + counts.fn)
    if precision is None or recall is None or precision + recall == 0:
        f1 = None
    else:
        f1 = 2 * precision * recall / (precision + recall)
    return {
        "truePositives": counts.tp,
        "falsePositives": counts.fp,
        "falseNegatives": counts.fn,
        "precision": _round(precision),
        "recall": _round(recall),
        "f1Score": _round(f1),
    }


def _ratio(numerator: int, denominator: int) -> Optional[float]:
    return None if denominator == 0 else numerator / denominator


def _round(value: Optional[float]) -> Optional[float]:
    return None if value is None else round(value, DECIMALS)
