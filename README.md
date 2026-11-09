# Motor de análisis de SegSoft

Servicio FastAPI (Python 3.11) que ejecuta las reglas de las políticas de seguridad
sobre los archivos de un repositorio. El backend Spring lo llama a través de
`POST /internal/execute-rule`.

## Desarrollo

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
uvicorn app.main:app --reload --port 8001
```

## Validación del motor

La suite de validación analiza los repositorios de referencia con el conjunto
completo de políticas, compara los hallazgos contra los esperados y calcula
precision, recall y F1, globales y por categoría.

```bash
make validate-engine                    # reportes en reports/
make validate-engine REPORT_DIR=out     # en otro directorio
make validate-engine PYTHON=.venv/bin/python
```

Equivale a `pytest tests/validation/`. El comando termina con código distinto de 0
si algún fixture tiene falsos positivos o falsos negativos, o si las métricas
globales no alcanzan los mínimos de `validation-thresholds.yml`. Corre también en
CI (GitHub Actions y el Jenkins de p2tools), que publican los reportes como artefactos.

**Reportes** (se generan aunque la suite falle):

- `validation-report.json`: métricas globales y por categoría, detalle por fixture,
  commit y fecha de ejecución. Las claves van en orden fijo, y una métrica cuyo
  denominador es 0 se reporta como `null`.
- `validation-report.md`: las mismas tablas para lectura, las diferencias de cada
  fixture que falla y el análisis cualitativo de los repositorios reales.

**Fixtures**, en `tests/fixtures/reference-repos/`:

| Carpeta | Contenido | Cuenta en las métricas |
|---|---|---|
| `vulnerable/<repo>/` | vulnerabilidades plantadas y su `expected.json` | sí |
| `secure/<repo>/` | código seguro, `expected.json` sin hallazgos (mide falsos positivos) | sí |
| `real/<repo>/` | repositorios reales de PDG ICESI, sin `expected.json` | no, solo análisis cualitativo |

Un hallazgo coincide con uno esperado si comparte archivo, categoría y línea
(`line: null` en las reglas que revisan el archivo completo), y cada esperado se
empareja como máximo una vez. Para agregar un fixture basta con crear su carpeta;
la suite lo descubre sola. Las reglas que se ejecutan vienen de
`tests/fixtures/rules_snapshot.json`, un snapshot de las reglas activas de la base
de datos.
