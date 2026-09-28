from app.executors.base import RuleExecutor


class RuleExecutorRegistry:

    def __init__(self):
        self._executors: dict[str, RuleExecutor] = {}

    def register(self, rule_type: str, executor: RuleExecutor) -> None:
        self._executors[rule_type] = executor

    def get(self, rule_type: str) -> RuleExecutor:
        if rule_type not in self._executors:
            raise ValueError(f"No executor registered for rule type: {rule_type!r}")
        return self._executors[rule_type]
