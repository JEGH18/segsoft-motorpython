import hashlib
import os
import time
import traceback

import structlog
from fastapi import APIRouter, Depends, Request
from starlette.concurrency import run_in_threadpool

from app.executors.errors import ControlledRuleError
from app.llm import suggestion_generator
from app.logging_config.setup import get_trace_id
from app.masking.secret_masker import SecretMasker
from app.models.finding import ExecuteRuleResponse, FindingResponse, RuleExecutionErrorResponse
from app.models.health import HealthResponse
from app.models.rule_request import ExecuteRuleBatchRequest, ExecuteRuleRequest
from app.security.sandbox import ensure_inside_sandbox
from app.security.token_auth import verify_token

router = APIRouter(prefix="/internal", tags=["internal"])

_masker = SecretMasker()
_logger = structlog.get_logger(__name__)


def _batch_timeout_seconds() -> float:
    try:
        return float(os.environ.get("BATCH_TIMEOUT_SECONDS", "120"))
    except ValueError:
        return 120.0


@router.post("/execute-rule", response_model=ExecuteRuleResponse, dependencies=[Depends(verify_token)])
async def execute_rule(request: Request, body: ExecuteRuleRequest) -> ExecuteRuleResponse:
    """One rule over one file. Kept for compatibility; the backend uses /execute-rule-batch."""
    trace_id = get_trace_id(request)
    logger = _logger.bind(traceId=trace_id, ruleId=body.ruleId, ruleType=body.type)
    logger.info("execute_rule_started")

    registry = request.app.state.registry
    # The executors are synchronous and CPU-bound: they run in the thread pool so a slow rule
    # never blocks the event loop (health checks and other requests keep being served).
    raw_findings, errors = await run_in_threadpool(
        _run_on_files, registry, body.type, body.payload, [body.artifactPath], body.ruleId, logger, None
    )

    findings = await _to_findings(body, raw_findings, logger)
    logger.info("execute_rule_completed", findingsCount=len(findings), errorsCount=len(errors))
    return ExecuteRuleResponse(findings=findings, errors=errors)


@router.post("/execute-rule-batch", response_model=ExecuteRuleResponse, dependencies=[Depends(verify_token)])
async def execute_rule_batch(request: Request, body: ExecuteRuleBatchRequest) -> ExecuteRuleResponse:
    """One rule over many files: one HTTP round trip instead of one per file.

    Each finding and each error carries the filePath it was produced for, exactly as it was
    sent in artifactPaths. Every file keeps its own per-rule deadline; once the whole batch
    exceeds BATCH_TIMEOUT_SECONDS the remaining files get a BATCH_TIMEOUT error instead of
    being analyzed, so the backend's read timeout is never reached.
    """
    trace_id = get_trace_id(request)
    logger = _logger.bind(traceId=trace_id, ruleId=body.ruleId, ruleType=body.type)
    logger.info("execute_rule_batch_started", files=len(body.artifactPaths))

    registry = request.app.state.registry
    batch_deadline = time.monotonic() + _batch_timeout_seconds()
    raw_findings, errors = await run_in_threadpool(
        _run_on_files, registry, body.type, body.payload, body.artifactPaths, body.ruleId, logger, batch_deadline
    )

    findings = await _to_findings(body, raw_findings, logger)
    logger.info("execute_rule_batch_completed", findingsCount=len(findings), errorsCount=len(errors))
    return ExecuteRuleResponse(findings=findings, errors=errors)


@router.get("/health", dependencies=[Depends(verify_token)])
async def health() -> HealthResponse:
    return HealthResponse(status="ok")


def _run_on_files(registry, rule_type, payload, paths, rule_id, logger, batch_deadline):
    """Runs the rule over each path. Returns (raw findings with their filePath, errors)."""
    raw_findings: list[dict] = []
    errors: list[RuleExecutionErrorResponse] = []

    try:
        executor = registry.get(rule_type)
    except Exception as exc:  # noqa: BLE001 -- unknown rule type: one error per file
        return [], [
            _error_from_exception(rule_id, "UNKNOWN_RULE_TYPE", str(exc), traceback.format_exc(), path)
            for path in paths
        ]

    for path in paths:
        if batch_deadline is not None and time.monotonic() >= batch_deadline:
            errors.append(_error_from_exception(
                rule_id, "BATCH_TIMEOUT",
                "El lote superó el tiempo máximo; el archivo no se analizó con esta regla", "", path))
            continue
        try:
            ensure_inside_sandbox(path)
            for finding in executor.execute(payload, path):
                # Always the path as requested (never a resolved one), so the caller can map it.
                finding["filePath"] = path
                raw_findings.append(finding)
        except ControlledRuleError as exc:
            errors.append(_error_from_exception(rule_id, exc.error_type, exc.message, traceback.format_exc(), path))
            logger.warning("execute_rule_controlled_error", errorType=exc.error_type, message=exc.message)
        except Exception as exc:  # noqa: BLE001
            errors.append(_error_from_exception(rule_id, "UNEXPECTED_ERROR", str(exc), traceback.format_exc(), path))
            logger.exception("execute_rule_unexpected_error", message=str(exc))

    return raw_findings, errors


async def _to_findings(body, raw_findings: list[dict], logger) -> list[FindingResponse]:
    # One LLM call per rule execution, not per match -- a rule that hits
    # 20 identical lines in a file doesn't need 20 near-duplicate
    # suggestions. is_enabled() short-circuits this to a no-op when the
    # feature flag is off (the default), so raw_findings' own
    # suggestedAction (always None today) reaches FindingResponse
    # unchanged and Java's existing static-text fallback takes over.
    llm_suggestion = None
    if raw_findings and suggestion_generator.is_enabled():
        representative_snippet = _masker.mask(raw_findings[0].get("evidenceSnippet") or "")
        llm_suggestion = await suggestion_generator.generate_suggestion(
            category=body.category or "UNKNOWN",
            cwe_id=body.cweId,
            evidence_snippet=representative_snippet or "",
            style_example=body.payload.get("suggestedAction"),
        )
        if llm_suggestion:
            logger.info("llm_suggestion_generated")

    return [
        FindingResponse(
            ruleId=body.ruleId,
            policyId=body.policyId,
            category=finding.get("category") or body.category or "UNKNOWN",
            filePath=finding["filePath"],
            lineNumber=finding.get("lineNumber"),
            fileSha256=finding.get("fileSha256"),
            severity=finding.get("severity") or body.severity or "MEDIUM",
            evidenceSnippet=_masker.mask(finding.get("evidenceSnippet") or ""),
            cweId=body.cweId,
            suggestedAction=llm_suggestion or finding.get("suggestedAction"),
        )
        for finding in raw_findings
    ]


def _error_from_exception(rule_id: str, error_type: str, message: str, stacktrace: str,
                          file_path: str | None = None) -> RuleExecutionErrorResponse:
    stack_hash = hashlib.sha256(stacktrace.encode("utf-8")).hexdigest()[:16]
    return RuleExecutionErrorResponse(
        ruleId=rule_id,
        errorType=error_type,
        message=message,
        stacktraceHash=stack_hash,
        errorCode=error_type,
        filePath=file_path,
    )
