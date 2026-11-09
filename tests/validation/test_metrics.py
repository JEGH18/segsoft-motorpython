import pytest

from engine_validation.matching import Finding, match_findings
from engine_validation.metrics import Counts, compute_metrics, counts_by_category, total_counts


def finding(category="XSS", line=1, file="a.py"):
    return Finding(file=file, line=line, category=category, severity="HIGH")


def test_known_values():
    # TP=3 FP=1 FN=2 -> precision 0.75, recall 0.6, F1 = 2*0.75*0.6/1.35 = 0.6667
    m = compute_metrics(Counts(tp=3, fp=1, fn=2))
    assert (m["truePositives"], m["falsePositives"], m["falseNegatives"]) == (3, 1, 2)
    assert m["precision"] == 0.75
    assert m["recall"] == 0.6
    assert m["f1Score"] == pytest.approx(0.6667)


def test_perfect_detection():
    assert compute_metrics(Counts(tp=31))["f1Score"] == 1.0


def test_zero_denominators_are_null():
    m = compute_metrics(Counts())
    assert m["precision"] is None and m["recall"] is None and m["f1Score"] is None


def test_precision_null_when_nothing_detected():
    m = compute_metrics(Counts(fn=4))
    assert m["precision"] is None
    assert m["recall"] == 0.0
    assert m["f1Score"] is None


def test_f1_null_when_precision_and_recall_are_zero():
    m = compute_metrics(Counts(fp=2, fn=3))
    assert m["precision"] == 0.0 and m["recall"] == 0.0
    assert m["f1Score"] is None


def test_counts_by_category_attributes_fp_to_actual_and_fn_to_expected():
    results = [
        match_findings([finding("XSS")], [finding("XSS")]),                       # TP XSS
        match_findings([finding("SQL_INJECTION")], []),                            # FN SQL_INJECTION
        match_findings([], [finding("INSECURE_DATA_HANDLING", file="clean.py")]),  # FP INSECURE_DATA_HANDLING
    ]
    by_category = counts_by_category(results, ["XSS", "SQL_INJECTION", "INSECURE_DATA_HANDLING", "AUTHENTICATION_FAILURE"])
    assert by_category["XSS"] == Counts(tp=1)
    assert by_category["SQL_INJECTION"] == Counts(fn=1)
    assert by_category["INSECURE_DATA_HANDLING"] == Counts(fp=1)
    assert by_category["AUTHENTICATION_FAILURE"] == Counts()
    assert total_counts(results) == Counts(tp=1, fp=1, fn=1)


def test_unknown_category_still_appears():
    results = [match_findings([], [finding("OTHER")])]
    assert counts_by_category(results, ["XSS"])["OTHER"] == Counts(fp=1)
