import re
from typing import Optional

# Group 1 keeps the key and the separator (and an opening quote, if any); the value is masked.
_SENSITIVE_PATTERNS = [
    r"(api[_-]?key[\"']?\s*[=:]\s*[\"']?)[^\s,;\"']+",
    r"(secret(?:[_-]?key)?[\"']?\s*[=:]\s*[\"']?)[^\s,;\"']+",
    r"(passw(?:or)?d[\"']?\s*[=:]\s*[\"']?)[^\s,;\"']+",
    r"(token[\"']?\s*[=:]\s*[\"']?)[^\s,;\"']+",
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
