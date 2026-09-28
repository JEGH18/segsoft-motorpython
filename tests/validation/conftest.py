import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="module")
def client():
    """Sobrescribe el `client` de function-scope de tests/conftest.py: este
    módulo hace ~500 llamadas HTTP contra el motor (23 reglas x archivos del
    dataset) y las cachea en un fixture module-scoped (engine_run_results),
    así que el TestClient necesita vivir el módulo completo, no un test."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="module", autouse=True)
def _set_token_env_module():
    """Versión module-scoped de _set_token_env (tests/conftest.py es
    function-scoped) -- necesaria porque engine_run_results es module-scoped
    y no puede depender de un fixture de menor scope."""
    import os

    previous = os.environ.get("INTERNAL_SERVICE_TOKEN")
    os.environ["INTERNAL_SERVICE_TOKEN"] = "test-internal-token"
    yield
    if previous is None:
        os.environ.pop("INTERNAL_SERVICE_TOKEN", None)
    else:
        os.environ["INTERNAL_SERVICE_TOKEN"] = previous


@pytest.fixture(scope="module")
def auth_headers():
    return {"X-Service-Token": "test-internal-token", "X-Trace-Id": "trace-validation-001"}
