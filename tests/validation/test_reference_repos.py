"""PDGSEGSOFT-23: valida precisión y cobertura del motor contra el dataset
de referencia en fixtures/reference-repos/.

Cada carpeta ahí es un mini-repo con vulnerabilidades plantadas a propósito
(o ninguna, en los "-clean") y su expected_findings.yml (ground truth). Este
test ejecuta cada regla ACTIVA real (fixtures/rules_snapshot.json, snapshot
de la base de datos tomado después de V29/V30) contra cada archivo del
dataset a través del mismo endpoint HTTP que usa el backend Spring en
producción (/internal/execute-rule), y compara lo que el motor encontró
contra lo que se sabe que hay.

precision_min / recall_min vienen de validation-thresholds.yml (raíz del
repo) -- el mismo archivo que ya dispara el job de CI en
.github/workflows/validate-engine.yml.
"""

import json
from collections import Counter
from pathlib import Path

import pytest
import yaml

FIXTURES_DIR = Path(__file__).resolve().parents[2] / "fixtures"
REPOS_DIR = FIXTURES_DIR / "reference-repos"
RULES_SNAPSHOT = FIXTURES_DIR / "rules_snapshot.json"


def _find_thresholds_file() -> Path:
    """Sube desde este archivo hasta encontrar validation-thresholds.yml.
    En el checkout normal vive en la raíz del monorepo (varios niveles arriba
    de backend/engine-python/tests/validation/); en el contenedor de CI/local
    donde /app *es* la raíz de engine-python, se monta directamente un nivel
    más arriba -- de ahí la búsqueda en vez de un parents[N] fijo."""
    for candidate in Path(__file__).resolve().parents:
        target = candidate / "validation-thresholds.yml"
        if target.exists():
            return target
    raise FileNotFoundError("No se encontró validation-thresholds.yml en ningún ancestro")


THRESHOLDS_FILE = _find_thresholds_file()

# Tipos de regla que el motor sabe ejecutar hoy contra archivos de código o
# manifiestos (AST_QUERY no tiene ninguna regla activa en el snapshot).
EXECUTABLE_TYPES = {"PATTERN_REGEX", "CONFIG_CHECK", "DEPENDENCY_CHECK"}


def _load_rules() -> list[dict]:
    rules = json.loads(RULES_SNAPSHOT.read_text(encoding="utf-8"))
    return [r for r in rules if r["type"] in EXECUTABLE_TYPES]


def _load_thresholds() -> dict:
    return yaml.safe_load(THRESHOLDS_FILE.read_text(encoding="utf-8"))


def _repo_dirs() -> list[Path]:
    return sorted(p for p in REPOS_DIR.iterdir() if p.is_dir())


def _files_in_repo(repo_dir: Path) -> list[Path]:
    return sorted(
        p for p in repo_dir.rglob("*")
        if p.is_file() and p.name != "expected_findings.yml"
    )


def _expected_counter(repo_dir: Path) -> Counter:
    data = yaml.safe_load((repo_dir / "expected_findings.yml").read_text(encoding="utf-8"))
    findings = data.get("findings") or []
    return Counter(
        (f["file"], f.get("line"), f["category"], f["severity"])
        for f in findings
    )


def _run_engine_against_repo(client, auth_headers, rules: list[dict], repo_dir: Path) -> Counter:
    actual = Counter()
    for file_path in _files_in_repo(repo_dir):
        rel_path = str(file_path.relative_to(repo_dir))
        for rule in rules:
            response = client.post(
                "/internal/execute-rule",
                headers=auth_headers,
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
            assert response.status_code == 200, (
                f"/internal/execute-rule falló para regla {rule['id']} sobre {file_path}: "
                f"{response.status_code} {response.text}"
            )
            body = response.json()
            assert body["errors"] == [], f"Regla {rule['id']} sobre {file_path} produjo errores: {body['errors']}"
            for finding in body["findings"]:
                actual[(rel_path, finding["lineNumber"], finding["category"], finding["severity"])] += 1
    return actual


def _precision_recall(actual: Counter, expected: Counter) -> tuple[float, float, int, int, int]:
    keys = set(actual) | set(expected)
    tp = fp = fn = 0
    for key in keys:
        a, e = actual.get(key, 0), expected.get(key, 0)
        tp += min(a, e)
        fp += max(0, a - e)
        fn += max(0, e - a)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    return precision, recall, tp, fp, fn


@pytest.fixture(scope="module")
def engine_run_results(client, auth_headers) -> dict:
    """Corre el motor una sola vez contra todo el dataset y cachea el resultado
    para que las distintas aserciones no repitan las ~500 llamadas HTTP."""
    rules = _load_rules()
    per_repo = {}
    for repo_dir in _repo_dirs():
        actual = _run_engine_against_repo(client, auth_headers, rules, repo_dir)
        expected = _expected_counter(repo_dir)
        per_repo[repo_dir.name] = {"actual": actual, "expected": expected}
    return per_repo


def test_reference_dataset_exists_and_is_populated():
    repos = _repo_dirs()
    assert len(repos) >= 5, "El dataset de referencia debería tener al menos 5 repos (2 sanos + 1 por categoría)"
    for repo_dir in repos:
        assert (repo_dir / "expected_findings.yml").exists(), f"{repo_dir.name} no tiene expected_findings.yml"
        assert _files_in_repo(repo_dir), f"{repo_dir.name} no tiene archivos de código"


def test_clean_repos_produce_zero_findings(engine_run_results):
    for repo_name in ("java-clean", "python-clean"):
        actual = engine_run_results[repo_name]["actual"]
        assert sum(actual.values()) == 0, (
            f"{repo_name} debía dar 0 hallazgos (mide falsos positivos) pero dio: {actual}"
        )


def test_overall_precision_and_recall_meet_thresholds(engine_run_results):
    thresholds = _load_thresholds()
    total_actual: Counter = Counter()
    total_expected: Counter = Counter()
    for result in engine_run_results.values():
        total_actual.update(result["actual"])
        total_expected.update(result["expected"])

    precision, recall, tp, fp, fn = _precision_recall(total_actual, total_expected)

    print(f"\n=== PDGSEGSOFT-23: precisión/cobertura global ===")
    print(f"TP={tp} FP={fp} FN={fn}")
    print(f"Precisión: {precision:.3f} (mínimo exigido: {thresholds['precision_min']})")
    print(f"Cobertura: {recall:.3f} (mínimo exigido: {thresholds['recall_min']})")

    assert precision >= thresholds["precision_min"], (
        f"Precisión {precision:.3f} por debajo del mínimo {thresholds['precision_min']}"
    )
    assert recall >= thresholds["recall_min"], (
        f"Cobertura {recall:.3f} por debajo del mínimo {thresholds['recall_min']}"
    )


def test_per_category_breakdown(engine_run_results):
    """No falla el build -- solo imprime la tabla que alimenta el capítulo 4."""
    thresholds = _load_thresholds()
    by_category_actual: dict[str, Counter] = {c: Counter() for c in thresholds["categories"]}
    by_category_expected: dict[str, Counter] = {c: Counter() for c in thresholds["categories"]}

    for result in engine_run_results.values():
        for key, count in result["actual"].items():
            category = key[2]
            by_category_actual.setdefault(category, Counter())[key] += count
        for key, count in result["expected"].items():
            category = key[2]
            by_category_expected.setdefault(category, Counter())[key] += count

    print("\n=== PDGSEGSOFT-23: desglose por categoría ===")
    print(f"{'Categoría':<28}{'Precisión':>10}{'Cobertura':>10}{'TP':>6}{'FP':>6}{'FN':>6}")
    for category in thresholds["categories"]:
        precision, recall, tp, fp, fn = _precision_recall(
            by_category_actual.get(category, Counter()),
            by_category_expected.get(category, Counter()),
        )
        print(f"{category:<28}{precision:>10.3f}{recall:>10.3f}{tp:>6}{fp:>6}{fn:>6}")
