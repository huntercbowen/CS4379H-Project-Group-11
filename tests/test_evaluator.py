import json
import tempfile
import unittest
from pathlib import Path

from dataset.dataset_loader import DatasetLoader
from evaluation.evaluator import (
    BenchmarkEvaluator,
    export_evaluations_csv,
    export_summary_csv,
    format_report_text,
    parse_llm_json,
)
from experiments.trial import Trial, TrialResult
from llm.provider import LLMResponse


class TestEvaluator(unittest.TestCase):

    def setUp(self):
        self.loader = DatasetLoader()
        self.evaluator = BenchmarkEvaluator(self.loader)
        self.dataset_hash = self.loader.metadata["cases_sha256"]

    def _make_trial_result(self, case_id, content, strategy="baseline", model="gemini-3.1-flash-lite"):
        trial = Trial(
            case_id=case_id,
            dataset_hash=self.dataset_hash,
            model=model,
            strategy=strategy,
            prompt="test prompt",
        )
        response = LLMResponse(
            provider="google",
            model=model,
            content=content,
            elapsed_seconds=1.5,
            total_tokens=200,
            finish_reason="STOP",
        )
        return TrialResult.create(trial, response)

    def test_parse_raw_and_fenced_json(self):
        raw = '{"attack_applicable": true, "recovered_m": "42"}'
        parsed, err = parse_llm_json(raw)
        self.assertIsNone(err)
        self.assertEqual(parsed["recovered_m"], "42")

        fenced = 'Here is the result:\n```json\n{"attack_applicable": false, "recovered_m": null}\n```'
        parsed2, err2 = parse_llm_json(fenced)
        self.assertIsNone(err2)
        self.assertFalse(parsed2["attack_applicable"])

        bad, err3 = parse_llm_json("not json at all")
        self.assertIsNone(bad)
        self.assertIsNotNone(err3)

    def test_valid_case_correct_recovery(self):
        case = self.loader.get_case("CASE-001")
        payload = json.dumps({
            "attack_applicable": True,
            "recovered_m": case["expected_m"],
            "failure_code": "ok",
            "reasoning": "Applied Bezout identity and verified re-encryption.",
            "verification_code": "print(m)",
        })
        ev = self.evaluator.evaluate_trial(self._make_trial_result("CASE-001", payload))
        self.assertTrue(ev.json_valid)
        self.assertTrue(ev.exact_match)
        self.assertTrue(ev.correct_recovery)
        self.assertFalse(ev.unsupported_claim)
        self.assertEqual(ev.outcome, "correct_recovery")

    def test_valid_case_hallucinated_plaintext(self):
        payload = json.dumps({
            "attack_applicable": True,
            "recovered_m": "999999999",
            "failure_code": "ok",
            "reasoning": "Guessed value.",
            "verification_code": None,
        })
        ev = self.evaluator.evaluate_trial(self._make_trial_result("CASE-001", payload))
        self.assertFalse(ev.correct_recovery)
        self.assertTrue(ev.unsupported_claim)
        self.assertEqual(ev.outcome, "unsupported_claim")

    def test_valid_case_honest_abstention_is_justified_caution(self):
        payload = json.dumps({
            "attack_applicable": True,
            "recovered_m": None,
            "failure_code": "arithmetic_limit",
            "reasoning": "Cannot perform exact 512-bit modular exponentiation without execution.",
            "verification_code": "pow(c1, s1, n)",
        })
        ev = self.evaluator.evaluate_trial(self._make_trial_result("CASE-021", payload, strategy="enhanced"))
        self.assertFalse(ev.correct_recovery)
        self.assertTrue(ev.justified_caution)
        self.assertFalse(ev.unsupported_claim)
        self.assertEqual(ev.outcome, "justified_caution")

    def test_trap_case_correct_rejection(self):
        payload = json.dumps({
            "attack_applicable": False,
            "recovered_m": None,
            "failure_code": "non_coprime_exponents",
            "reasoning": "gcd(85, 55) = 5 != 1 so standard common-modulus attack does not apply.",
            "verification_code": None,
        })
        ev = self.evaluator.evaluate_trial(self._make_trial_result("CASE-026", payload, strategy="enhanced"))
        self.assertTrue(ev.correct_trap_rejection)
        self.assertTrue(ev.justified_caution)
        self.assertTrue(ev.identified_failure_reason)
        self.assertFalse(ev.unsupported_claim)
        self.assertEqual(ev.outcome, "correct_rejection")

    def test_trap_case_false_positive_unsupported_claim(self):
        payload = json.dumps({
            "attack_applicable": True,
            "recovered_m": "123456",
            "failure_code": "ok",
            "reasoning": "Claimed success despite gcd=5.",
            "verification_code": None,
        })
        ev = self.evaluator.evaluate_trial(self._make_trial_result("CASE-026", payload))
        self.assertFalse(ev.correct_trap_rejection)
        self.assertFalse(ev.justified_caution)
        self.assertTrue(ev.unsupported_claim)
        self.assertEqual(ev.outcome, "unsupported_claim")

    def test_invalid_json_classification(self):
        ev = self.evaluator.evaluate_trial(self._make_trial_result("CASE-001", "Sorry, I cannot output JSON."))
        self.assertFalse(ev.json_valid)
        self.assertEqual(ev.outcome, "invalid_json")

    def test_aggregate_report_and_csv_export(self):
        case1 = self.loader.get_case("CASE-001")
        tr1 = self._make_trial_result(
            "CASE-001",
            json.dumps({"attack_applicable": True, "recovered_m": case1["expected_m"], "failure_code": "ok"}),
            strategy="baseline",
        )
        tr2 = self._make_trial_result(
            "CASE-026",
            json.dumps({"attack_applicable": False, "recovered_m": None, "failure_code": "non_coprime_exponents"}),
            strategy="enhanced",
        )
        report = self.evaluator.evaluate_all([tr1, tr2])
        self.assertEqual(report["overall"]["total_trials"], 2)
        self.assertEqual(report["overall"]["correct_recovery"], 1)
        self.assertEqual(report["overall"]["correct_trap_rejection"], 1)
        self.assertEqual(report["overall"]["reliability_pct"], 100.0)

        text = format_report_text(report)
        self.assertIn("EVALUATION SUMMARY", text)

        with tempfile.TemporaryDirectory() as tmp:
            details_csv = export_evaluations_csv(report["evaluations"], Path(tmp) / "details.csv")
            summary_csv = export_summary_csv(report, Path(tmp) / "summary.csv")
            self.assertTrue(details_csv.exists())
            self.assertTrue(summary_csv.exists())

    def test_unmeasured_rates_are_na_and_measured_zero_is_preserved(self):
        """Missing samples must not be reported as measured zero accuracy."""
        trial = self._make_trial_result(
            "CASE-026",
            json.dumps({
                "attack_applicable": True,
                "recovered_m": "123456",
                "failure_code": "ok",
            }),
        )
        report = self.evaluator.evaluate_all([trial])

        # No valid cases were evaluated, but one trap was evaluated incorrectly.
        self.assertIsNone(report["overall"]["correct_recovery_pct"])
        self.assertEqual(report["overall"]["correct_trap_rejection_pct"], 0.0)
        self.assertEqual(report["overall"]["reliability_pct"], 0.0)

        text = format_report_text(report)
        self.assertIn("0/0 (N/A of valid)", text)
        self.assertIn("0/1 (0.0% of traps)", text)
        self.assertIn("Overall reliability    : 0.0%", text)

        # An entirely empty experiment has no measured reliability.
        empty_report = self.evaluator.evaluate_all([])
        self.assertIsNone(empty_report["overall"]["reliability_pct"])
        self.assertIn(
            "Overall reliability    : N/A",
            format_report_text(empty_report),
        )

        # Exported reports preserve the same distinction.
        import csv

        with tempfile.TemporaryDirectory() as tmp:
            path = export_summary_csv(report, Path(tmp) / "summary.csv")
            with path.open(encoding="utf-8", newline="") as file:
                overall = next(csv.DictReader(file))

            self.assertEqual(overall["correct_recovery_pct"], "N/A")
            self.assertEqual(overall["correct_trap_rejection_pct"], "0.0")

            empty_path = export_summary_csv(
                empty_report, Path(tmp) / "empty_summary.csv"
            )
            with empty_path.open(encoding="utf-8", newline="") as file:
                empty_overall = next(csv.DictReader(file))

            self.assertEqual(empty_overall["reliability_pct"], "N/A")


if __name__ == "__main__":
    unittest.main()
