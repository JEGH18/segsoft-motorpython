"""validation-report.json (para máquinas) y validation-report.md (para personas).

El JSON se escribe con las claves ordenadas, así que dos ejecuciones con el
mismo resultado producen el mismo archivo salvo los campos de VOLATILE_FIELDS.
"""

import json
import os
import subprocess
from collections import Counter
from pathlib import Path
from typing import Optional

from .metrics import compute_metrics, counts_by_category, counts_of, total_counts
from .runner import FixtureResult, SuiteRun

JSON_NAME = "validation-report.json"
MARKDOWN_NAME = "validation-report.md"
SCHEMA_VERSION = 1

# Cambian de una ejecución a otra sin que cambie el código ni los fixtures.
VOLATILE_FIELDS = ("generatedAt", "durationMs")


def current_commit(repo_dir: Path) -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repo_dir, capture_output=True, text=True, check=True, timeout=10
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        # Agentes de CI sin git instalado: Jenkins exporta GIT_COMMIT y GitHub Actions GITHUB_SHA.
        return os.environ.get("GIT_COMMIT") or os.environ.get("GITHUB_SHA") or "unknown"


def build_report(
    run: SuiteRun,
    *,
    categories: list[str],
    thresholds: dict,
    commit: str,
    generated_at: str,
    rules_snapshot: str,
) -> dict:
    matches = [r.match for r in run.ground_truth_results]
    global_metrics = compute_metrics(total_counts(matches))
    global_metrics["meetsThresholds"] = _meets(global_metrics, thresholds)
    return {
        "schemaVersion": SCHEMA_VERSION,
        "commit": commit,
        "generatedAt": generated_at,
        "durationMs": run.duration_ms,
        "rulesSnapshot": {"file": rules_snapshot, "executableRules": run.rules_count},
        "matchCriteria": ["file", "category", "line"],
        "thresholds": {"precisionMin": thresholds["precision_min"], "recallMin": thresholds["recall_min"]},
        "passed": all(m.passed for m in matches),
        "global": global_metrics,
        "categories": {
            name: compute_metrics(counts)
            for name, counts in counts_by_category(matches, categories).items()
        },
        "fixtures": [_fixture_entry(r) for r in run.ground_truth_results],
        "realRepositories": [_real_entry(r) for r in run.results if r.match is None],
    }


def _meets(metrics: dict, thresholds: dict) -> bool:
    precision, recall = metrics["precision"], metrics["recall"]
    return (
        precision is not None and recall is not None
        and precision >= thresholds["precision_min"] and recall >= thresholds["recall_min"]
    )


def _fixture_entry(result: FixtureResult) -> dict:
    entry = {
        "id": result.fixture.id,
        "name": result.fixture.name,
        "kind": result.fixture.kind,
        "filesAnalyzed": result.files_analyzed,
        "expectedFindings": len(result.expected),
        "detectedFindings": len(result.actual),
        "passed": result.match.passed,
        "falsePositiveFindings": [f.to_dict() for f in result.match.false_positives],
        "falseNegativeFindings": [f.to_dict() for f in result.match.false_negatives],
    }
    entry.update(compute_metrics(counts_of(result.match)))
    return entry


def _real_entry(result: FixtureResult) -> dict:
    return {
        "id": result.fixture.id,
        "name": result.fixture.name,
        "filesAnalyzed": result.files_analyzed,
        "totalFindings": len(result.actual),
        "findingsByCategory": dict(sorted(Counter(f.category for f in result.actual).items())),
        "findingsBySeverity": dict(sorted(Counter(f.severity for f in result.actual).items())),
        "findings": [f.to_dict() for f in result.actual],
    }


def write_json(report: dict, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, sort_keys=True, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def write_reports(report: dict, out_dir: Path) -> tuple[Path, Path]:
    json_path = write_json(report, out_dir / JSON_NAME)
    md_path = out_dir / MARKDOWN_NAME
    md_path.write_text(render_markdown(report), encoding="utf-8")
    return json_path, md_path


def comparable(report: dict) -> dict:
    return {k: v for k, v in report.items() if k not in VOLATILE_FIELDS}


def diff_reports(a, b, path: str = "") -> list[str]:
    """Rutas (p. ej. categories.XSS.precision) cuyo valor difiere entre dos reportes."""
    if isinstance(a, dict) and isinstance(b, dict):
        differences = []
        for key in sorted(set(a) | set(b)):
            child = f"{path}.{key}" if path else str(key)
            if key not in a or key not in b:
                differences.append(f"{child}: {a.get(key, '<ausente>')!r} -> {b.get(key, '<ausente>')!r}")
            else:
                differences.extend(diff_reports(a[key], b[key], child))
        return differences
    if isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        differences = []
        for i, (x, y) in enumerate(zip(a, b)):
            differences.extend(diff_reports(x, y, f"{path}[{i}]"))
        return differences
    return [] if a == b else [f"{path}: {a!r} -> {b!r}"]


# --- Markdown ---------------------------------------------------------------

_KIND_LABEL = {"vulnerable": "Vulnerable", "secure": "Seguro"}


def render_markdown(report: dict) -> str:
    g = report["global"]
    t = report["thresholds"]
    lines = [
        "# Reporte de validación del motor",
        "",
        f"- **Commit:** `{report['commit']}`",
        f"- **Fecha de ejecución:** {report['generatedAt']}",
        f"- **Duración:** {report['durationMs']} ms",
        f"- **Reglas ejecutadas:** {report['rulesSnapshot']['executableRules']} "
        f"(`{report['rulesSnapshot']['file']}`)",
        "- **Criterio de coincidencia:** archivo, categoría y línea",
        f"- **Resultado:** {'APROBADA' if report['passed'] else 'FALLIDA'} "
        f"(umbrales: precision ≥ {t['precisionMin']}, recall ≥ {t['recallMin']}; "
        f"{'se cumplen' if g['meetsThresholds'] else 'no se cumplen'})",
        "",
        "## Métricas globales",
        "",
        "| TP | FP | FN | Precision | Recall | F1 |",
        "|---:|---:|---:|---:|---:|---:|",
        f"| {g['truePositives']} | {g['falsePositives']} | {g['falseNegatives']} "
        f"| {_fmt(g['precision'])} | {_fmt(g['recall'])} | {_fmt(g['f1Score'])} |",
        "",
        "## Métricas por categoría",
        "",
        "| Categoría | TP | FP | FN | Precision | Recall | F1 |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for name, m in report["categories"].items():
        lines.append(
            f"| {name} | {m['truePositives']} | {m['falsePositives']} | {m['falseNegatives']} "
            f"| {_fmt(m['precision'])} | {_fmt(m['recall'])} | {_fmt(m['f1Score'])} |"
        )
    lines += [
        "",
        "Una métrica en blanco (—) indica que su denominador es 0.",
        "",
        "## Detalle por fixture",
        "",
        "| Fixture | Tipo | Archivos | Esperados | Detectados | TP | FP | FN | Resultado |",
        "|---|---|---:|---:|---:|---:|---:|---:|---|",
    ]
    for f in report["fixtures"]:
        lines.append(
            f"| {f['name']} | {_KIND_LABEL.get(f['kind'], f['kind'])} | {f['filesAnalyzed']} "
            f"| {f['expectedFindings']} | {f['detectedFindings']} | {f['truePositives']} "
            f"| {f['falsePositives']} | {f['falseNegatives']} | {'Pasa' if f['passed'] else 'Falla'} |"
        )
    failed = [f for f in report["fixtures"] if not f["passed"]]
    for f in failed:
        lines += ["", f"### {f['id']}: diferencias", ""]
        for title, items in (("Falsos positivos", f["falsePositiveFindings"]),
                             ("Falsos negativos", f["falseNegativeFindings"])):
            if items:
                lines.append(f"**{title}:**")
                lines.append("")
                lines += [f"- {_describe(item)}" for item in items]
                lines.append("")
    if lines[-1] != "":
        lines.append("")
    lines += ["## Análisis cualitativo de repositorios reales de PDG ICESI", ""]
    real = report["realRepositories"]
    if not real:
        lines.append(
            "Todavía no hay repositorios reales en `tests/fixtures/reference-repos/real/`. "
            "Cuando se agreguen, aquí aparecerán sus hallazgos para revisarlos uno a uno. "
            "No tienen ground truth, así que no cuentan en las métricas anteriores."
        )
    for repo in real:
        by_category = ", ".join(f"{k}: {v}" for k, v in repo["findingsByCategory"].items()) or "ninguno"
        by_severity = ", ".join(f"{k}: {v}" for k, v in repo["findingsBySeverity"].items()) or "ninguno"
        lines += [
            f"### {repo['name']}",
            "",
            f"- Archivos analizados: {repo['filesAnalyzed']}",
            f"- Hallazgos: {repo['totalFindings']} (por categoría: {by_category}; por severidad: {by_severity})",
            "",
        ]
        if repo["findings"]:
            lines += [
                "| Archivo | Línea | Categoría | Severidad | ¿Problema real? |",
                "|---|---:|---|---|---|",
            ]
            lines += [
                f"| {x['file']} | {'—' if x['line'] is None else x['line']} | {x['category']} | {x['severity']} |  |"
                for x in repo["findings"]
            ]
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _fmt(value: Optional[float]) -> str:
    return "—" if value is None else f"{value:.3f}"


def _describe(item: dict) -> str:
    line = "sin línea" if item["line"] is None else f"línea {item['line']}"
    return f"`{item['file']}` ({line}) {item['category']} {item['severity']}, regla `{item['ruleId']}`"
