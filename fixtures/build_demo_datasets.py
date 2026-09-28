#!/usr/bin/env python3
"""Empaqueta los fixtures de reference-repos/ en 3 ZIPs listos para subir a
SegSoft (POST /api/v1/repositories, multipart "file") y mostrarle al tutor
los 3 datasets por severidad que pidió: sano / con warnings / con fallas
graves. Uso:

    python3 fixtures/build_demo_datasets.py [directorio_salida]

Por defecto escribe en /tmp. No se comitean los .zip generados.

Nota (ver hallazgo de validación en tests/validation/): el "sano" NO va a
dar 0 hallazgos en la demo -- las reglas CONFIG_CHECK "must_exist" (MFA,
checksum, CSP, antigüedad de dependencias) marcan como "falta configuración"
cualquier archivo que no sea el .yml correcto, así que hasta el pom.xml y el
.java sanos van a salir con hallazgos CRITICAL/HIGH espurios. Es el mismo bug
documentado, no un vulnerabilidad nueva -- avisar antes de mostrarlo.
"""
import sys
import zipfile
from pathlib import Path

FIXTURES_DIR = Path(__file__).resolve().parent
REPOS_DIR = FIXTURES_DIR / "reference-repos"


def _add_dir(zf: zipfile.ZipFile, source_dir: Path, arc_prefix: str) -> None:
    for path in sorted(source_dir.rglob("*")):
        if path.is_file() and path.name != "expected_findings.yml":
            arcname = f"{arc_prefix}/{path.relative_to(source_dir)}"
            zf.write(path, arcname)


def build(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(out_dir / "dataset-sano.zip", "w", zipfile.ZIP_DEFLATED) as zf:
        _add_dir(zf, REPOS_DIR / "java-clean", "java")
        _add_dir(zf, REPOS_DIR / "python-clean", "python")

    with zipfile.ZipFile(out_dir / "dataset-warnings.zip", "w", zipfile.ZIP_DEFLATED) as zf:
        _add_dir(zf, FIXTURES_DIR / "demo-warnings-only", ".")

    with zipfile.ZipFile(out_dir / "dataset-fallas-graves.zip", "w", zipfile.ZIP_DEFLATED) as zf:
        for name in (
            "sql-injection",
            "auth-failure",
            "xss",
            "insecure-data-handling",
            "dependency-vulnerability",
        ):
            _add_dir(zf, REPOS_DIR / name, name)

    for zip_path in sorted(out_dir.glob("dataset-*.zip")):
        print(f"{zip_path} ({zip_path.stat().st_size} bytes)")


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/tmp")
    build(target)
