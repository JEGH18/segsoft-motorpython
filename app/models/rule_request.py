from pydantic import BaseModel
from typing import Optional


class ExecuteRuleRequest(BaseModel):
    ruleId: str
    type: str
    payload: dict
    artifactPath: str
    policyId: Optional[str] = None
    category: Optional[str] = None
    severity: Optional[str] = None
    cweId: Optional[str] = None
