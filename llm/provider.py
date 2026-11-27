from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class LLMResponse:
    """Standardized response from an LLM provider."""

    provider: str
    model: str
    content: str
    elapsed_seconds: float

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    finish_reason: str | None = None
    response_id: str | None = None


class LLMProviderError(Exception):
    """Raised when an LLM request fails."""


class LLMProvider(ABC):
    """Interface for supported LLM providers."""

    @abstractmethod
    def generate(self, prompt: str, model: str) -> LLMResponse:
        raise NotImplementedError