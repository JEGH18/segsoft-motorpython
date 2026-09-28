import re
from typing import Optional

_SENSITIVE_PATTERNS = [
    r"(api[_-]?key\s*[=:]\s*)[^\s,;]+",
    r"(secret\s*[=:]\s*)[^\s,;]+",
    r"(password\s*[=:]\s*)[^\s,;]+",
    r"(token\s*[=:]\s*)[^\s,;]+",
]


class SecretMasker:

    def __init__(self):
        self._compiled = [
            re.compile(p, re.IGNORECASE) for p in _SENSITIVE_PATTERNS
        ]

    def mask(self, text: Optional[str]) -> Optional[str]:
        if text is None:
            return None
        for pattern in self._compiled:
            text = pattern.sub(r"\g<1>*****", text)
        return text
