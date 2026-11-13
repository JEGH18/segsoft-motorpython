import time
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request

from app.executors.ast_executor import AstExecutor
from app.executors.config_executor import ConfigExecutor
from app.executors.dependency_executor import DependencyExecutor
from app.executors.regex_executor import RegexExecutor
from app.executors.registry import RuleExecutorRegistry
from app.logging_config.setup import TRACE_HEADER, configure_logging, resolve_trace_id
from app.routers import internal

# At import, before uvicorn logs its first line: every line of the process is JSON.
configure_logging()

registry = RuleExecutorRegistry()
_logger = structlog.get_logger("app.requests")


@asynccontextmanager
async def lifespan(app: FastAPI):
    registry.register("PATTERN_REGEX", RegexExecutor())
    registry.register("AST_QUERY", AstExecutor())
    registry.register("CONFIG_CHECK", ConfigExecutor())
    registry.register("DEPENDENCY_CHECK", DependencyExecutor())
    app.state.registry = registry
    yield


app = FastAPI(
    title="pdgseg-engine",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(internal.router)


@app.middleware("http")
async def trace_id_middleware(request: Request, call_next):
    """Binds the backend's X-Trace-Id to every log written while serving the request."""
    trace_id = resolve_trace_id(request.headers.get(TRACE_HEADER))
    request.state.trace_id = trace_id
    structlog.contextvars.clear_contextvars()
    structlog.contextvars.bind_contextvars(traceId=trace_id)
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        _logger.exception("request_failed", method=request.method, path=request.url.path)
        structlog.contextvars.clear_contextvars()
        raise
    duration_ms = round((time.perf_counter() - started) * 1000, 1)
    response.headers[TRACE_HEADER] = trace_id
    # Health checks are frequent and say nothing new: DEBUG, not INFO.
    log = _logger.debug if request.url.path.endswith("/health") else _logger.info
    log("request_completed", method=request.method, path=request.url.path,
        status=response.status_code, durationMs=duration_ms)
    structlog.contextvars.clear_contextvars()
    return response


@app.get("/")
def root():
    return {"service": "pdgseg-engine", "status": "running"}
