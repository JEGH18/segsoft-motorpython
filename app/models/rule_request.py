from typing import Optional

from pydantic import BaseModel, Field

# One batch request carries one rule and many files of the same repository.
MAX_BATCH_FILES = 500


class ExecuteRuleRequest(BaseModel):
    ruleId: str
    type: str
    payload: dict
    artifactPath: str
    policyId: Optional[str] = None
    category: Optional[str] = None
    severity: Optional[str] = None
    cweId: Optional[str] = None


class ExecuteRuleBatchRequest(BaseModel):
    ruleId: str
    type: str
    payload: dict
    artifactPaths: list[str] = Field(min_length=1, max_length=MAX_BATCH_FILES)
    policyId: Optional[str] = None
    category: Optional[str] = None
    severity: Optional[str] = None
    cweId: Optional[str] = None
