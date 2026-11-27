import unittest
import tempfile

from pathlib import Path

from experiments.trial import Trial, TrialResult
from experiments.response_store import ResponseStore
from llm.provider import LLMResponse


class TestResponseStore(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.path = Path(self.temp_dir.name) / "test.jsonl"
        self.store = ResponseStore(self.path)

        self.trial = Trial(
            case_id="CASE-001",
            dataset_hash="test-hash",
            model="gemini-3.1-flash-lite",
            strategy="baseline",
            prompt="Test prompt"
        )

        self.response = LLMResponse(
            provider="google",
            model="gemini-3.1-flash-lite",
            content='{"attack_applicable": true}',
            elapsed_seconds=1.0,
            total_tokens=150,
            finish_reason="STOP"
        )

        self.result = TrialResult.create(
            self.trial,
            self.response
        )

    def test_empty_store(self):
        self.assertEqual(self.store.load_all(), [])

    def test_save_result(self):
        self.assertTrue(self.store.save(self.result))
        self.assertTrue(self.path.exists())

    def test_round_trip(self):
        self.store.save(self.result)

        results = self.store.load_all()

        self.assertEqual(results[0], self.result)

    def test_completed_trial(self):
        self.store.save(self.result)

        self.assertTrue(
            self.store.is_completed(self.trial)
        )

    def test_duplicate_prevention(self):
        self.assertTrue(self.store.save(self.result))
        self.assertFalse(self.store.save(self.result))

        self.assertEqual(len(self.store.load_all()), 1)

    def test_persistent_storage(self):
        self.store.save(self.result)

        new_store = ResponseStore(self.path)

        self.assertTrue(
            new_store.is_completed(self.trial)
        )

    def test_different_prompt(self):
        different_trial = Trial(
            case_id=self.trial.case_id,
            dataset_hash=self.trial.dataset_hash,
            model=self.trial.model,
            strategy=self.trial.strategy,
            prompt="Modified prompt"
        )

        self.assertNotEqual(
            self.trial.identifier,
            different_trial.identifier
        )

    def test_different_trial_number(self):
        different_trial = Trial(
            case_id=self.trial.case_id,
            dataset_hash=self.trial.dataset_hash,
            model=self.trial.model,
            strategy=self.trial.strategy,
            prompt=self.trial.prompt,
            trial_number=2
        )

        self.assertNotEqual(
            self.trial.identifier,
            different_trial.identifier
        )


if __name__ == "__main__":
    unittest.main()