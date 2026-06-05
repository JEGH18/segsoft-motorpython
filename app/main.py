from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.executors.ast_executor import AstExecutor
from app.executors.config_executor import ConfigExecutor
from app.executors.dependency_executor import DependencyExecutor
from app.executors.regex_executor import RegexExecutor
from app.executors.registry import RuleExecutorRegistry
from app.logging_config.setup import configure_logging
from app.routers import internal

registry = RuleExecutorRegistry()


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
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


@app.get("/")
def root():
    return {"service": "pdgseg-engine", "status": "running"}
