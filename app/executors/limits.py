"""Time limits for rule execution.

Rule patterns are written by administrators but run against code uploaded by anyone, so a
pattern with catastrophic backtracking (or a huge minified line) must not be able to hang the
engine. Python's ``re`` cannot be interrupted: it holds the GIL for the whole match, so a
``future.result(timeout=...)`` in another thread never even gets to fire. The third-party
``regex`` module accepts a ``timeout`` per match and releases the GIL while matching
(``concurrent=True``), which is what every executor uses through this module.
"""

import os
import time
from functools import lru_cache

import regex

from app.executors.errors import ControlledRuleError


def _float_env(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


# Budget for one rule over one file.
RULE_TIMEOUT_SECONDS = _float_env("RULE_TIMEOUT_SECONDS", 5.0)
# Files above this size are not parsed with ast (which cannot be interrupted); the line-based
# heuristics, which honour the deadline, are used instead.
MAX_AST_FILE_BYTES = _int_env("MAX_AST_FILE_BYTES", 2 * 1024 * 1024)

TIMEOUT_MESSAGE = "La ejecución de la regla superó el timeout permitido"


class Deadline:
    """A point in time after which the current rule execution must stop."""

    def __init__(self, seconds: float | None = None):
        self._end = time.monotonic() + (RULE_TIMEOUT_SECONDS if seconds is None else seconds)

    def remaining(self) -> float:
        """Seconds left; raises RULE_TIMEOUT once the deadline has passed."""
        left = self._end - time.monotonic()
        if left <= 0:
            raise ControlledRuleError("RULE_TIMEOUT", TIMEOUT_MESSAGE)
        return left


@lru_cache(maxsize=256)
def compile_pattern(pattern: str, flags: int = 0):
    """Compiles with ``regex`` in its ``re``-compatible mode (V0); raises INVALID_REGEX."""
    try:
        return regex.compile(pattern, flags | regex.V0)
    except (regex.error, TypeError, ValueError) as exc:
        raise ControlledRuleError("INVALID_REGEX", f"Regex inválida: {exc}") from exc


def finditer(compiled, text: str, deadline: Deadline):
    """Like ``compiled.finditer(text)`` but bounded by the deadline."""
    try:
        for match in compiled.finditer(text, timeout=deadline.remaining(), concurrent=True):
            yield match
            deadline.remaining()
    except TimeoutError as exc:
        raise ControlledRuleError("RULE_TIMEOUT", TIMEOUT_MESSAGE) from exc


def search(compiled, text: str, deadline: Deadline):
    """Like ``compiled.search(text)`` but bounded by the deadline."""
    try:
        return compiled.search(text, timeout=deadline.remaining(), concurrent=True)
    except TimeoutError as exc:
        raise ControlledRuleError("RULE_TIMEOUT", TIMEOUT_MESSAGE) from exc
