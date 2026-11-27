import json

from pathlib import Path
from dataclasses import asdict

from experiments.trial import Trial, TrialResult
from llm.provider import LLMResponse


class ResponseStore:
    """Persist and retrieve completed experimental trials."""

    DEFAULT_PATH = (
        Path(__file__).resolve().parent.parent
        / "results"
        / "development.jsonl"
    )

    def __init__(self, file_path=None):
        self.file_path = (
            Path(file_path)
            if file_path is not None
            else self.DEFAULT_PATH
        )

    def save(self, result: TrialResult):
        """Append a completed trial to the response file."""

        if result.trial.identifier in self.get_completed_trials():
            return False

        self.file_path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        with self.file_path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(asdict(result)) + "\n")

        return True

    def load_all(self):
        """Load saved experimental results."""

        if not self.file_path.exists():
            return []

        results = []

        with self.file_path.open("r", encoding="utf-8") as file:
            for line in file:
                if not line.strip():
                    continue

                record = json.loads(line)

                result = TrialResult(
                    trial=Trial(**record["trial"]),
                    response=LLMResponse(**record["response"]),
                    timestamp=record["timestamp"]
                )

                results.append(result)

        return results

    def get_completed_trials(self):
        """Return identifiers of previously completed trials."""

        return {
            result.trial.identifier
            for result in self.load_all()
        }

    def is_completed(self, trial: Trial):
        return trial.identifier in self.get_completed_trials()