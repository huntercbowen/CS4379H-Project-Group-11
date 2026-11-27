import unittest

from llm.prompts import PromptBuilder, PromptStrategy


class TestPromptBuilder(unittest.TestCase):

    def setUp(self):
        self.builder = PromptBuilder()

        self.parameters = {
            "n1": "5780239",
            "n2": "5780239",
            "e1": "17",
            "e2": "29",
            "c1": "303530",
            "c2": "3579394"
        }

    def test_baseline_prompt(self):
        prompt = self.builder.build(
            self.parameters,
            PromptStrategy.BASELINE
        )

        self.assertIn("standard RSA common-modulus", prompt)

        self.assertNotIn(
            "Before reaching a conclusion:",
            prompt
        )

    def test_enhanced_prompt(self):
        prompt = self.builder.build(
            self.parameters,
            PromptStrategy.ENHANCED
        )

        self.assertIn(
            "Before reaching a conclusion:",
            prompt
        )

        self.assertIn(
            "Verify any recovered plaintext",
            prompt
        )

    def test_public_parameters_included(self):
        prompt = self.builder.build(
            self.parameters,
            PromptStrategy.BASELINE
        )

        for field, value in self.parameters.items():
            self.assertIn(f"{field} = {value}", prompt)

    def test_ground_truth_excluded(self):
        parameters = {
            **self.parameters,
            "expected_m": "SECRET_ANSWER",
            "category": "SECRET_CATEGORY",
            "expected_failure_code": "SECRET_FAILURE",
            "note": "SECRET_NOTE"
        }

        for strategy in PromptStrategy:
            prompt = self.builder.build(
                parameters,
                strategy
            )

            self.assertNotIn("SECRET_ANSWER", prompt)
            self.assertNotIn("SECRET_CATEGORY", prompt)
            self.assertNotIn("SECRET_FAILURE", prompt)
            self.assertNotIn("SECRET_NOTE", prompt)

    def test_invalid_strategy(self):
        with self.assertRaises(ValueError):
            self.builder.build(
                self.parameters,
                "invalid"
            )

    def test_missing_parameter(self):
        parameters = self.parameters.copy()
        del parameters["n1"]

        with self.assertRaises(KeyError):
            self.builder.build(
                parameters,
                PromptStrategy.BASELINE
            )

    def test_response_format(self):
        for strategy in PromptStrategy:
            prompt = self.builder.build(
                self.parameters,
                strategy
            )

            self.assertIn('"attack_applicable"', prompt)
            self.assertIn('"recovered_m"', prompt)
            self.assertIn('"failure_code"', prompt)
            self.assertIn('"reasoning"', prompt)
            self.assertIn('"verification_code"', prompt)


if __name__ == "__main__":
    unittest.main()