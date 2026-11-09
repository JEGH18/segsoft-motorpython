"""Rutas y umbrales de la suite, y el paso completo ejecutar + armar reporte
que comparten la suite y la prueba de reproducibilidad."""

import os
from datetime import datetime, timezone
from pathlib import Path

import yaml

from .discovery import discover_fixtures
from .report import build_report, current_commit
from .runner import SuiteRun, run_suite

REPO_ROOT = Path(__file__).resolve().parents[3]
FIXTURES_ROOT = REPO_ROOT / "tests" / "fixtures" / "reference-repos"
RULES_SNAPSHOT = REPO_ROOT / "tests" / "fixtures" / "rules_snapshot.json"


def find_thresholds_file() -> Path:
    """Sube desde este archivo hasta encontrar validation-thresholds.yml: en el
    repositorio del motor vive en la raíz, y en el checkout del monorepo varios
    niveles más arriba."""
    for candidate in Path(__file__).resolve().parents:
        target = candidate / "validation-thresholds.yml"
        if target.exists():
            return target
    raise FileNotFoundError("No se encontró validation-thresholds.yml en ningún ancestro")


def load_thresholds() -> dict:
    return yaml.safe_load(find_thresholds_file().read_text(encoding="utf-8"))


def report_dir() -> Path:
    return Path(os.environ.get("VALIDATION_REPORT_DIR") or REPO_ROOT / "reports")


def run_and_build_report(client, headers: dict) -> tuple[SuiteRun, dict]:
    thresholds = load_thresholds()
    run = run_suite(client, headers, discover_fixtures(FIXTURES_ROOT), RULES_SNAPSHOT)
    report = build_report(
        run,
        categories=thresholds["categories"],
        thresholds=thresholds,
        commit=current_commit(REPO_ROOT),
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        rules_snapshot=RULES_SNAPSHOT.relative_to(REPO_ROOT).as_posix(),
    )
    return run, report
