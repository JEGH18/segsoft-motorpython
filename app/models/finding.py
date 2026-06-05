from typing import Optional

from pydantic import BaseModel


class FindingResponse(BaseModel):
    ruleId: str
    policyId: Optional[str] = None
    category: str
    filePath: str
    lineNumber: Optional[int] = None
    fileSha256: Optional[str] = None
    severity: str
    evidenceSnippet: str
    cweId: Optional[str] = None
    suggestedAction: Optional[str] = None


class RuleExecutionErrorResponse(BaseModel):
    ruleId: str
    errorType: str
    message: str
    stacktraceHash: str
    errorCode: str


class ExecuteRuleResponse(BaseModel):
    findings: list[FindingResponse]
    errors: list[RuleExecutionErrorResponse]
