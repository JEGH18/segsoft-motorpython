<h1 align="center">🛡️ SegSoft · Analysis Engine</h1>

<p align="center">
  FastAPI service that executes SegSoft's security rules against source code and returns structured findings.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python 3.11" />
  <img src="https://img.shields.io/badge/FastAPI-0.111-009688?style=flat-square&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/tree--sitter-AST-4B5563?style=flat-square" alt="tree-sitter" />
  <img src="https://img.shields.io/badge/pytest-tested-0A9EDC?style=flat-square&logo=pytest&logoColor=white" alt="pytest" />
  <img src="https://img.shields.io/badge/Bandit-checked-FACC15?style=flat-square" alt="Bandit" />
</p>

---

## Overview

The engine is an internal service of [SegSoft](https://github.com/JEGH18/segsoft-backend), a security-policy compliance analyzer built as a capstone project at Icesi University. The backend sends one rule at a time together with the path of the repository in a shared sandbox; the engine runs the rule over the files and returns findings with severity, location and evidence.

## How rules are executed

| Executor | Detects |
|---|---|
| **Regex** | Code patterns linked to SQL injection, XSS, authentication failures and insecure data handling |
| **AST (tree-sitter)** | Structural patterns that need syntax awareness, beyond plain text matching |
| **Config** | Insecure settings in configuration files |
| **Dependency** | Known-vulnerable packages (via `pip-audit`) |

Every finding goes through a **secret masker** before it leaves the service, so credentials found in code are never returned in clear text. Optionally, an LLM writes a short, code-specific **remediation suggestion** per finding (disabled by default with `LLM_SUGGESTIONS_ENABLED=false`).

## API

| Method | Path | Description |
|---|---|---|
| `POST` | `/internal/execute-rule` | Runs a rule over a repository and returns findings |
| `GET` | `/internal/health` | Health check |

Both endpoints require the shared `INTERNAL_SERVICE_TOKEN`; the engine is not exposed publicly.

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
uvicorn app.main:app --reload --port 8001
```

Or with Docker, using the `Dockerfile` in this repository.

## Tests

```bash
pytest
```

- `tests/unit`: one suite per executor, the registry, the secret masker and the suggestion generator
- `tests/validation`: runs the rules against reference repositories and checks the results against `validation-thresholds.yml`

## Stack

FastAPI · Pydantic 2 · Uvicorn · tree-sitter · httpx · tenacity · structlog · pip-audit · pytest · Bandit

## Related repositories

[segsoft-backend](https://github.com/JEGH18/segsoft-backend) · [segsoft-frontend](https://github.com/JEGH18/segsoft-frontend) · [segsoft-docs](https://github.com/JEGH18/segsoft-docs) · [SegSoft-Pruebas](https://github.com/JEGH18/SegSoft-Pruebas)

> The official repositories live on Icesi University's p2tools Bitbucket; GitHub hosts a mirror.
