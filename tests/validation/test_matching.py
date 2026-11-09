from engine_validation.matching import Finding, match_findings


def finding(file="a.py", line=1, category="XSS", severity="HIGH", rule_id="r1"):
    return Finding(file=file, line=line, category=category, severity=severity, rule_id=rule_id)


def test_identical_findings_are_true_positives():
    result = match_findings([finding()], [finding()])
    assert len(result.true_positives) == 1
    assert result.false_positives == [] and result.false_negatives == []
    assert result.passed


def test_match_ignores_severity_and_rule():
    # El criterio es archivo, categoría y línea: severidad y regla no deciden.
    result = match_findings([finding(severity="HIGH", rule_id="r1")], [finding(severity="LOW", rule_id="r2")])
    assert len(result.true_positives) == 1 and result.passed


def test_different_file_category_or_line_do_not_match():
    expected = [finding()]
    for actual in (finding(file="b.py"), finding(category="SQL_INJECTION"), finding(line=2)):
        result = match_findings(expected, [actual])
        assert result.true_positives == []
        assert result.false_positives == [actual]
        assert result.false_negatives == expected
        assert not result.passed


def test_findings_without_line_match_each_other():
    result = match_findings([finding(line=None)], [finding(line=None)])
    assert result.passed


def test_each_expected_is_matched_at_most_once():
    result = match_findings([finding()], [finding(), finding()])
    assert len(result.true_positives) == 1
    assert len(result.false_positives) == 1


def test_duplicate_expected_need_duplicate_actual():
    # Como DEPENDENCY_CHECK: varias dependencias vulnerables en el mismo manifiesto, sin línea.
    expected = [finding(line=None), finding(line=None), finding(line=None)]
    result = match_findings(expected, [finding(line=None), finding(line=None)])
    assert len(result.true_positives) == 2
    assert len(result.false_negatives) == 1
    assert result.false_positives == []


def test_prefers_same_rule_when_several_candidates_share_the_key():
    expected = [finding(severity="CRITICAL", rule_id="crit"), finding(severity="MEDIUM", rule_id="med")]
    actual = [finding(severity="MEDIUM", rule_id="med"), finding(severity="CRITICAL", rule_id="crit")]
    result = match_findings(expected, actual)
    assert all(e.rule_id == a.rule_id for e, a in result.true_positives)


def test_secure_fixture_with_findings_has_only_false_positives():
    result = match_findings([], [finding(), finding(file="b.py")])
    assert result.true_positives == [] and result.false_negatives == []
    assert len(result.false_positives) == 2 and not result.passed


def test_empty_on_both_sides_passes():
    assert match_findings([], []).passed
