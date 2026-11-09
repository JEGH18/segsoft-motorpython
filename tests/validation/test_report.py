import json
from pathlib import Path

from engine_validation.discovery import Fixture, discover_fixtures, load_expected, source_files
from engine_validation.matching import Finding, match_findings
from engine_validation.report import build_report, comparable, diff_reports, render_markdown, write_json
from engine_validation.runner import FixtureResult, SuiteRun

THRESHOLDS = {"precision_min": 0.95, "recall_min": 0.90, "categories": ["XSS", "SQL_INJECTION"]}


def _run() -> SuiteRun:
    xss = Finding("a.py", 3, "XSS", "HIGH", "r1")
    vulnerable = Fixture("xss", "vulnerable", Path("/x"))
    secure = Fixture("clean", "secure", Path("/y"))
    real = Fixture("segsoft", "real", Path("/z"))
    return SuiteRun(rules_count=2, duration_ms=5, results=[
        FixtureResult(vulnerable, 1, [xss], [xss], match_findings([xss], [xss])),
        FixtureResult(secure, 1, [], [], match_findings([], [])),
        FixtureResult(real, 4, [Finding("b.py", None, "XSS", "MEDIUM", "r2")]),
    ])


def _report(**overrides) -> dict:
    args = dict(categories=THRESHOLDS["categories"], thresholds=THRESHOLDS, commit="abc123",
                generated_at="2026-11-08T12:00:00+00:00", rules_snapshot="tests/fixtures/rules_snapshot.json")
    args.update(overrides)
    return build_report(_run(), **args)


def test_report_contains_global_category_and_fixture_metrics():
    report = _report()
    assert report["passed"] is True
    assert report["global"]["truePositives"] == 1 and report["global"]["meetsThresholds"]
    assert report["categories"]["SQL_INJECTION"]["precision"] is None   # sin datos -> null
    assert [f["id"] for f in report["fixtures"]] == ["vulnerable/xss", "secure/clean"]
    assert report["realRepositories"][0]["findingsByCategory"] == {"XSS": 1}
    assert report["commit"] == "abc123" and report["generatedAt"]


def test_json_keys_are_written_in_deterministic_order(tmp_path):
    path = write_json({"b": 1, "a": {"d": None, "c": 2}}, tmp_path / "r.json")
    assert path.read_text(encoding="utf-8") == '{\n  "a": {\n    "c": 2,\n    "d": null\n  },\n  "b": 1\n}\n'


def test_volatile_fields_are_ignored_when_comparing():
    a = _report(generated_at="2026-11-08T12:00:00+00:00")
    b = _report(generated_at="2026-11-09T08:30:00+00:00")
    b["durationMs"] = 999
    assert diff_reports(comparable(a), comparable(b)) == []


def test_diff_names_the_metric_that_changed():
    a, b = _report(), _report()
    b["categories"]["XSS"]["precision"] = 0.5
    assert diff_reports(comparable(a), comparable(b)) == ["categories.XSS.precision: 1.0 -> 0.5"]


def test_markdown_has_summary_tables_fixture_detail_and_real_repositories():
    markdown = render_markdown(_report())
    assert "`abc123`" in markdown and "2026-11-08T12:00:00+00:00" in markdown
    assert "| SQL_INJECTION | 0 | 0 | 0 | — | — | — |" in markdown
    assert "| xss | Vulnerable |" in markdown and "| clean | Seguro |" in markdown
    assert "### segsoft" in markdown and "| b.py | — | XSS | MEDIUM |  |" in markdown


def test_markdown_lists_differences_of_a_failing_fixture():
    run = _run()
    missing = Finding("a.py", 9, "XSS", "HIGH", "r9")
    run.results[0].match = match_findings([missing], run.results[0].actual)
    run.results[0].expected = [missing]
    report = build_report(run, categories=THRESHOLDS["categories"], thresholds=THRESHOLDS, commit="abc",
                          generated_at="2026-11-08T12:00:00+00:00", rules_snapshot="s.json")
    markdown = render_markdown(report)
    assert report["passed"] is False
    assert "### vulnerable/xss: diferencias" in markdown
    assert "**Falsos negativos:**" in markdown and "`a.py` (línea 9)" in markdown


def test_new_fixture_is_discovered_without_code_changes(tmp_path):
    repo = tmp_path / "vulnerable" / "nuevo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "App.java").write_text("class App {}", encoding="utf-8")
    (repo / ".git").mkdir()
    (repo / ".git" / "config").write_text("[core]", encoding="utf-8")
    (repo / "expected.json").write_text(json.dumps({"findings": [
        {"file": "src/App.java", "line": 1, "category": "XSS", "severity": "HIGH", "ruleId": "r"}
    ]}), encoding="utf-8")
    (tmp_path / "real" / "segsoft").mkdir(parents=True)

    fixtures = discover_fixtures(tmp_path)
    assert [f.id for f in fixtures] == ["vulnerable/nuevo", "real/segsoft"]
    assert [p.name for p in source_files(fixtures[0])] == ["App.java"]
    assert load_expected(fixtures[0])[0].file == "src/App.java"
    assert not fixtures[1].has_ground_truth
