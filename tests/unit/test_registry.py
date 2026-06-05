import pytest
from app.executors.registry import RuleExecutorRegistry
from app.executors.base import RuleExecutor


class DummyExecutor(RuleExecutor):
    def execute(self, payload, artifact_path):
        return [{"hit": True}]


def test_register_and_get():
    registry = RuleExecutorRegistry()
    registry.register("DUMMY", DummyExecutor())
    executor = registry.get("DUMMY")
    assert executor.execute({}, "") == [{"hit": True}]


def test_get_unknown_type_raises_value_error():
    registry = RuleExecutorRegistry()
    with pytest.raises(ValueError, match="UNKNOWN_TYPE"):
        registry.get("UNKNOWN_TYPE")


def test_all_four_rule_types_registered_in_main():
    from app.executors.regex_executor import RegexExecutor
    from app.executors.ast_executor import AstExecutor
    from app.executors.config_executor import ConfigExecutor
    from app.executors.dependency_executor import DependencyExecutor

    registry = RuleExecutorRegistry()
    registry.register("PATTERN_REGEX", RegexExecutor())
    registry.register("AST_QUERY", AstExecutor())
    registry.register("CONFIG_CHECK", ConfigExecutor())
    registry.register("DEPENDENCY_CHECK", DependencyExecutor())

    for rule_type in ("PATTERN_REGEX", "AST_QUERY", "CONFIG_CHECK", "DEPENDENCY_CHECK"):
        executor = registry.get(rule_type)
        assert isinstance(executor, RuleExecutor)
