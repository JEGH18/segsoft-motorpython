"""Suite de validación automatizada del motor (PDGSEGSOFT-23).

Analiza cada fixture de tests/fixtures/reference-repos/ con el conjunto
completo de políticas, compara los hallazgos obtenidos contra expected.json
(archivo, categoría y línea) y genera validation-report.json y
validation-report.md en reports/ (o en VALIDATION_REPORT_DIR).

Cada fixture con ground truth (vulnerable/ y secure/) es un caso de prueba
propio: pasa si aparecen todos los hallazgos esperados y no hay ninguno de
más. Los repositorios de real/ se analizan y van al reporte, pero no tienen
caso de prueba porque no hay contra qué compararlos.

Uso: make validate-engine  (o pytest tests/validation/)
"""

import json

import pytest

from engine_validation.config import FIXTURES_ROOT, load_thresholds, report_dir, run_and_build_report
from engine_validation.discovery import discover_fixtures, load_expected, source_files
from engine_validation.report import JSON_NAME, MARKDOWN_NAME, write_reports

FIXTURES = discover_fixtures(FIXTURES_ROOT)
GROUND_TRUTH_FIXTURES = [f for f in FIXTURES if f.has_ground_truth]


@pytest.fixture(scope="module")
def suite(client, auth_headers):
    """Corre el motor una sola vez contra todo el dataset (unas 500 llamadas
    HTTP) y escribe los reportes antes de las aserciones, para que existan
    también cuando la suite falla."""
    run, report = run_and_build_report(client, auth_headers)
    paths = write_reports(report, report_dir())
    return run, report, paths


def test_dataset_has_vulnerable_and_secure_fixtures_covering_every_category():
    kinds = {f.kind for f in GROUND_TRUTH_FIXTURES}
    assert {"vulnerable", "secure"} <= kinds, f"Faltan fixtures vulnerables o seguros en {FIXTURES_ROOT}"
    covered = set()
    for fixture in GROUND_TRUTH_FIXTURES:
        assert source_files(fixture), f"{fixture.id} no tiene archivos para analizar"
        expected = load_expected(fixture)
        if fixture.kind == "vulnerable":
            assert expected, f"{fixture.id} es vulnerable pero no declara hallazgos esperados"
        covered.update(f.category for f in expected)
    missing = set(load_thresholds()["categories"]) - covered
    assert not missing, f"Ningún fixture vulnerable cubre: {sorted(missing)}"


@pytest.mark.parametrize("fixture", GROUND_TRUTH_FIXTURES, ids=lambda f: f.id)
def test_fixture_findings_match_expected(fixture, suite):
    run, _, _ = suite
    match = run.result_for(fixture.id).match
    problems = [f"FP {f.describe()}" for f in match.false_positives]
    problems += [f"FN {f.describe()}" for f in match.false_negatives]
    if not match.passed:
        pytest.fail(
            f"{fixture.id}: {len(match.false_positives)} falsos positivos y "
            f"{len(match.false_negatives)} falsos negativos\n  " + "\n  ".join(problems),
            pytrace=False,
        )


def test_global_metrics_meet_thresholds(suite):
    _, report, _ = suite
    g, t = report["global"], report["thresholds"]
    print(
        f"\nTP={g['truePositives']} FP={g['falsePositives']} FN={g['falseNegatives']} "
        f"precision={g['precision']} recall={g['recall']} f1={g['f1Score']}"
    )
    assert g["meetsThresholds"], (
        f"precision {g['precision']} (mínimo {t['precisionMin']}) o "
        f"recall {g['recall']} (mínimo {t['recallMin']}) por debajo del umbral"
    )


def test_reports_are_written_with_commit_and_date(suite):
    _, report, (json_path, md_path) = suite
    assert json_path.name == JSON_NAME and md_path.name == MARKDOWN_NAME
    written = json.loads(json_path.read_text(encoding="utf-8"))
    assert written == json.loads(json.dumps(report))
    assert written["commit"] and written["generatedAt"]
    assert set(written["categories"]) >= set(load_thresholds()["categories"])
    markdown = md_path.read_text(encoding="utf-8")
    for section in ("## Métricas globales", "## Métricas por categoría", "## Detalle por fixture",
                    "## Análisis cualitativo de repositorios reales de PDG ICESI"):
        assert section in markdown
    assert written["commit"] in markdown and written["generatedAt"] in markdown
