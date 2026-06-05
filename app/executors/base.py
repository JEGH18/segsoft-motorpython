from abc import ABC, abstractmethod


class RuleExecutor(ABC):

    @abstractmethod
    def execute(self, payload: dict, artifact_path: str) -> list:
        ...
