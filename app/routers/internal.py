import hashlib
import traceback

import structlog
from fastapi import APIRouter, Depends, Request

from app.executors.errors import ControlledRuleError
from app.logging_config.setup import get_trace_id
from app.models.finding import ExecuteRuleResponse, FindingResponse, RuleExecutionErrorResponse
from app.masking.secret_masker import SecretMasker
from app.models.health import HealthResponse
from app.models.rule_request import ExecuteRuleRequest
from app.security.token_auth import verify_token

router = APIRouter(prefix="/internal", tags=["internal"])

_masker = SecretMasker()
_logger = structlog.get_logger(__name__)


@router.post("/execute-rule", response_model=ExecuteRuleResponse, dependencies=[Depends(verify_token)])
async def execute_rule(request: Request, body: ExecuteRuleRequest) -> ExecuteRuleResponse:
    trace_id = get_trace_id(request)
    logger = _logger.bind(traceId=trace_id, ruleId=body.ruleId, ruleType=body.type)
    logger.info("execute_rule_started")

    registry = request.app.state.registry
    findings: list[FindingResponse] = []
    errors: list[RuleExecutionErrorResponse] = []

    try:
        executor = registry.get(body.type)
        raw_findings = executor.execute(body.payload, body.artifactPath)
        for finding in raw_findings:
            findings.append(
                FindingResponse(
                    ruleId=body.ruleId,
                    policyId=body.policyId,
                    category=finding.get("category") or body.category or "UNKNOWN",
                    filePath=finding.get("filePath") or body.artifactPath,
                    lineNumber=finding.get("lineNumber"),
                    fileSha256=finding.get("fileSha256"),
                    severity=finding.get("severity") or body.severity or "MEDIUM",
                    evidenceSnippet=_masker.mask(finding.get("evidenceSnippet") or ""),
                    cweId=body.cweId,
                    suggestedAction=finding.get("suggestedAction"),
                )
            )
    except ControlledRuleError as exc:
        errors.append(_error_from_exception(body.ruleId, exc.error_type, exc.message, traceback.format_exc()))
        logger.warning("execute_rule_controlled_error", errorType=exc.error_type, message=exc.message)
    except Exception as exc:  # noqa: BLE001
        errors.append(_error_from_exception(body.ruleId, "UNEXPECTED_ERROR", str(exc), traceback.format_exc()))
        logger.exception("execute_rule_unexpected_error", message=str(exc))

    logger.info("execute_rule_completed", findingsCount=len(findings), errorsCount=len(errors))
    return ExecuteRuleResponse(findings=findings, errors=errors)


@router.get("/health", dependencies=[Depends(verify_token)])
async def health() -> HealthResponse:
    return HealthResponse(status="ok")


def _error_from_exception(rule_id: str, error_type: str, message: str, stacktrace: str) -> RuleExecutionErrorResponse:
    stack_hash = hashlib.sha256(stacktrace.encode("utf-8")).hexdigest()[:16]
    return RuleExecutionErrorResponse(
        ruleId=rule_id,
        errorType=error_type,
        message=message,
        stacktraceHash=stack_hash,
        errorCode=error_type,
    )
