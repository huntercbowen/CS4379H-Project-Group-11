from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256

from llm.provider import LLMResponse


@dataclass(frozen=True)
class Trial:
    """Configuration for one experimental trial."""

    case_id: str
    dataset_hash: str
    model: str
    strategy: str
    prompt: str
    trial_number: int = 1

    @property
    def prompt_hash(self):
        return sha256(
            self.prompt.encode("utf-8")
        ).hexdigest()

    @property
    def identifier(self):
        """Uniquely identify this experimental trial."""

        return (
            self.dataset_hash,
            self.case_id,
            self.model,
            self.strategy,
            self.prompt_hash,
            self.trial_number
        )


@dataclass(frozen=True)
class TrialResult:
    """Result of a completed experimental trial."""

    trial: Trial
    response: LLMResponse
    timestamp: str

    @classmethod
    def create(cls, trial, response):
        return cls(
            trial=trial,
            response=response,
            timestamp=datetime.now(timezone.utc).isoformat()
        )