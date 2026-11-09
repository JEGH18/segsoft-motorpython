"""RNF-03: dos ejecuciones consecutivas sin cambios en el código ni en los
fixtures producen las mismas métricas.

Corre la suite completa dos veces, escribe cada validation-report.json en su
propio directorio y los compara después de quitar los campos que cambian
siempre (fecha y duración)."""

import json

from engine_validation.config import run_and_build_report
from engine_validation.report import JSON_NAME, comparable, diff_reports, write_json


def test_two_consecutive_runs_produce_identical_reports(client, auth_headers, tmp_path):
    reports = []
    for attempt in (1, 2):
        _, report = run_and_build_report(client, auth_headers)
        path = write_json(report, tmp_path / f"run-{attempt}" / JSON_NAME)
        reports.append(json.loads(path.read_text(encoding="utf-8")))

    differences = diff_reports(comparable(reports[0]), comparable(reports[1]))
    assert not differences, "Las métricas cambiaron entre ejecuciones:\n  " + "\n  ".join(differences)
