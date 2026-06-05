# segsoft-motorpython

Motor de análisis estático de **SegSoft** — ejecuta reglas de seguridad sobre archivos de código fuente. Proyecto de grado (PDG) — Universidad Icesi.

## Descripción

Microservicio FastAPI que recibe una regla y la ruta de un archivo, ejecuta el executor correspondiente y devuelve los hallazgos encontrados. Es llamado exclusivamente por el backend Spring (`segsoft-backend`).

## Tecnologías

| Componente | Versión |
|---|---|
| Python | 3.11+ |
| FastAPI | 0.111+ |
| Uvicorn | 0.30+ |
| PyYAML | 6.0+ |

## Tipos de reglas soportados

| Tipo | Executor | Descripción |
|---|---|---|
| `PATTERN_REGEX` | `RegexExecutor` | Busca un patrón regex línea a línea en el archivo |
| `AST_QUERY` | `AstExecutor` | Análisis de árbol sintáctico (AST) |
| `CONFIG_CHECK` | `ConfigExecutor` | Verifica claves en archivos de configuración (`.yml`, `.yaml`, `.properties`, `.env`, `.toml`, etc.) |
| `DEPENDENCY_CHECK` | `DependencyExecutor` | Detecta dependencias con CVEs conocidos en `pom.xml`, `package.json` y `requirements.txt` |

## Requisitos previos

- Python 3.11 o superior

## Cómo ejecutar

```bash
# 1. Crear entorno virtual e instalar dependencias (solo la primera vez)
python3 -m venv .venv
.venv/bin/pip install -e .

# 2. Iniciar el motor
INTERNAL_SERVICE_TOKEN=dev-internal-token \
  .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 18001
```

El motor queda disponible en `http://localhost:18001`.

## Autenticación

Todas las rutas internas requieren el header `X-Service-Token` con el valor del token configurado en `INTERNAL_SERVICE_TOKEN`. El backend Spring envía este token automáticamente.

## Endpoint principal

```
POST /internal/execute-rule
X-Service-Token: <token>

{
  "ruleId": "uuid",
  "type": "PATTERN_REGEX",
  "payload": { "pattern": "executeQuery\\s*\\(.*\\+", "description": "..." },
  "artifactPath": "/tmp/pdgseg-sandbox/<userId>/<repoId>/src/UserDao.java"
}
```

**Respuesta:**
```json
{
  "findings": [
    {
      "ruleId": "uuid",
      "filePath": "/tmp/...",
      "lineNumber": 7,
      "evidenceSnippet": "stmt.executeQuery(\"SELECT * FROM...\" + id)",
      "severity": "CRITICAL",
      "category": "SQL_INJECTION"
    }
  ],
  "errors": []
}
```

## Estructura del proyecto

```
app/
├── main.py                  # FastAPI app + registro de executors
├── routers/
│   └── internal.py          # Endpoint /internal/execute-rule y /internal/health
├── executors/
│   ├── base.py              # Clase abstracta RuleExecutor
│   ├── regex_executor.py    # PATTERN_REGEX
│   ├── ast_executor.py      # AST_QUERY
│   ├── config_executor.py   # CONFIG_CHECK
│   ├── dependency_executor.py  # DEPENDENCY_CHECK
│   └── registry.py          # Registro de executors por tipo
├── models/                  # Modelos Pydantic (request/response)
├── masking/                 # Enmascaramiento de secretos en evidencia
└── security/                # Validación del token de servicio

tests/
└── unit/                    # Tests unitarios por executor
```

## Esquema del payload por tipo de regla

### PATTERN_REGEX
```json
{ "pattern": "<regex>", "description": "..." }
```

### CONFIG_CHECK
```json
{
  "checks": [
    { "key": "server.ssl.enabled", "not_value": "false" },
    { "key": "mfa.required.roles", "must_exist": true },
    { "key": "some.key", "pattern": "regex_contra_el_valor" }
  ]
}
```

### DEPENDENCY_CHECK
```json
{
  "known_vulnerable": [
    { "ecosystem": "maven", "group": "org.apache.logging.log4j", "artifact": "log4j-core", "below_version": "2.17.1", "cve": "CVE-2021-44228" },
    { "ecosystem": "npm", "package": "lodash", "below_version": "4.17.21", "cve": "CVE-2021-23337" },
    { "ecosystem": "pypi", "package": "requests", "below_version": "2.20.0", "cve": "CVE-2018-18074" }
  ]
}
```
