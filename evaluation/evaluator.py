"""Automated evaluation and scoring engine for RSA Common-Modulus LLM trials.

Group 11 (Quanta Correspondent) — CS 4379H Cryptography
Evaluates persisted LLM responses against deterministic ground truth from
`data/cases.json` and `crypto/rsa_math.verify_candidate_plaintext`.

Metrics scored per trial (matching the Group 11 experimental rubric):
  - correct_recovery   : Valid case where the model recovered exact ground-truth m.
  - justified_caution  : Trap case accurately rejected (without fabricated m), OR
                         honest abstention without false applicability claims.
  - unsupported_claim  : Fabricated/wrong recovered_m, false positive on a trap case,
                         or false negative claiming a valid case is not applicable.
  - invalid_json       : Output could not be parsed into the required JSON object.

Can be imported by `BenchmarkService` or executed standalone:
    python -m evaluation.evaluator --results results/development.jsonl
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from crypto.rsa_math import verify_candidate_plaintext
from dataset.dataset_loader import DatasetLoader
from experiments.response_store import ResponseStore
from experiments.trial import TrialResult


FAILURE_KEYWORDS: Dict[str, Tuple[str, ...]] = {
    "non_coprime_exponents": ("non_coprime", "coprime", "gcd", "common factor", "not relatively prime"),
    "different_messages": ("different_message", "different plaintext", "distinct message", "m1 != m2", "re-encrypt", "mismatch"),
    "distinct_moduli": ("distinct_mod", "different mod", "n1 != n2", "not shared", "same modulus"),
    "ciphertext_out_of_range": ("out_of_range", "out of range", "c >= n", "c1 >= n", "c2 >= n", "greater than n", "exceeds modulus"),
    "non_invertible_ciphertext": ("non_invertible", "not invertible", "no inverse", "modular inverse", "gcd(c"),
}


@dataclass(frozen=True)
class TrialEvaluation:
    """Detailed verification and rubric score for a single saved LLM trial."""

    case_id: str
    category: str
    modulus_bits: int
    model: str
    strategy: str
    trial_number: int
    expected_applicable: bool
    expected_failure_code: str

    json_valid: bool
    claimed_applicable: Optional[bool]
    claimed_recovered_m: Optional[str]
    claimed_failure_code: Optional[str]
    has_verification_code: bool

    exact_match: bool
    reencrypts_to_c1: bool
    reencrypts_to_c2: bool
    identified_failure_reason: bool

    correct_recovery: bool
    correct_trap_rejection: bool
    justified_caution: bool
    unsupported_claim: bool
    outcome: str

    elapsed_seconds: float
    total_tokens: int
    finish_reason: Optional[str]
    notes: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def parse_llm_json(content: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Parse an LLM response into a JSON object, tolerating markdown code fences.

    Returns:
        Tuple (parsed_dict_or_None, error_message_or_None).
    """
    if not content or not content.strip():
        return None, "Empty response content."

    cleaned = content.strip()

    # 1. Direct JSON parse
    try:
        parsed = json.loads(cleaned)
        if isinstance(parsed, dict):
            return parsed, None
        return None, f"Expected JSON object, got {type(parsed).__name__}."
    except json.JSONDecodeError:
        pass

    # 2. Extract from ```json ... ``` or ``` ... ``` fences
    fence_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", cleaned, flags=re.DOTALL | re.IGNORECASE)
    if fence_match:
        try:
            parsed = json.loads(fence_match.group(1))
            if isinstance(parsed, dict):
                return parsed, None
        except json.JSONDecodeError:
            pass

    # 3. Fallback: extract outermost braces if prose surrounds the JSON object
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end > start:
        try:
            parsed = json.loads(cleaned[start : end + 1])
            if isinstance(parsed, dict):
                return parsed, None
        except json.JSONDecodeError as err:
            return None, f"Invalid JSON: {err.msg}"

    return None, "Response did not contain a valid JSON object."


def _normalize_optional_bool(value: Any) -> Optional[bool]:
    """Coerce JSON boolean (or string 'true'/'false') to bool or None."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        low = value.strip().lower()
        if low == "true":
            return True
        if low == "false":
            return False
        if low in ("null", "none", "unknown", "uncertain", ""):
            return None
    return None


def _normalize_optional_str(value: Any) -> Optional[str]:
    """Normalize optional string/int fields; treat empty or 'null' strings as None."""
    if value is None:
        return None
    text = str(value).strip()
    if not text or text.lower() in ("null", "none"):
        return None
    return text


def _matches_expected_failure(
    expected_code: str,
    claimed_code: Optional[str],
    reasoning: Optional[str],
) -> bool:
    """Check whether the model identified the true precondition failure."""
    if expected_code == "ok":
        return (claimed_code or "").strip().lower() == "ok"

    combined = f"{claimed_code or ''} {reasoning or ''}".lower()
    if expected_code.lower() in combined:
        return True

    keywords = FAILURE_KEYWORDS.get(expected_code, ())
    return any(kw in combined for kw in keywords)


class BenchmarkEvaluator:
    """Scores saved `TrialResult` records against ground truth in `DatasetLoader`."""

    def __init__(self, dataset_loader: DatasetLoader):
        self.dataset_loader = dataset_loader

    def evaluate_trial(self, trial_result: TrialResult) -> TrialEvaluation:
        """Verify and classify one completed experimental trial."""
        trial = trial_result.trial
        response = trial_result.response
        case = self.dataset_loader.get_case(trial.case_id)

        expected_applicable = bool(case["attack_applicable"])
        expected_code = str(case["expected_failure_code"])

        parsed, parse_error = parse_llm_json(response.content)
        if parsed is None:
            return TrialEvaluation(
                case_id=trial.case_id,
                category=case["category"],
                modulus_bits=int(case["modulus_bits"]),
                model=trial.model,
                strategy=trial.strategy,
                trial_number=trial.trial_number,
                expected_applicable=expected_applicable,
                expected_failure_code=expected_code,
                json_valid=False,
                claimed_applicable=None,
                claimed_recovered_m=None,
                claimed_failure_code=None,
                has_verification_code=False,
                exact_match=False,
                reencrypts_to_c1=False,
                reencrypts_to_c2=False,
                identified_failure_reason=False,
                correct_recovery=False,
                correct_trap_rejection=False,
                justified_caution=False,
                unsupported_claim=False,
                outcome="invalid_json",
                elapsed_seconds=float(response.elapsed_seconds),
                total_tokens=int(response.total_tokens),
                finish_reason=response.finish_reason,
                notes=parse_error or "Invalid JSON.",
            )

        claimed_applicable = _normalize_optional_bool(parsed.get("attack_applicable"))
        claimed_m = _normalize_optional_str(parsed.get("recovered_m"))
        claimed_code = _normalize_optional_str(parsed.get("failure_code"))
        reasoning = _normalize_optional_str(parsed.get("reasoning"))
        verification_code = _normalize_optional_str(parsed.get("verification_code"))

        # Deterministic mathematical verification using crypto/rsa_math.py
        checks = verify_candidate_plaintext(case, claimed_m)
        exact_match = checks["exact_match"]
        reenc_1 = checks["reencrypts_to_c1"]
        reenc_2 = checks["reencrypts_to_c2"]
        identified_reason = _matches_expected_failure(expected_code, claimed_code, reasoning)

        correct_recovery = False
        correct_trap_rejection = False
        justified_caution = False
        unsupported_claim = False
        notes_parts: List[str] = []

        if expected_applicable:
            # Ground truth: attack IS applicable
            if exact_match:
                correct_recovery = True
                outcome = "correct_recovery"
                notes_parts.append("Exact plaintext recovered and verified.")
            elif claimed_m is not None:
                unsupported_claim = True
                outcome = "unsupported_claim"
                notes_parts.append("Hallucinated or inaccurate recovered_m on valid case.")
            elif claimed_applicable is False:
                unsupported_claim = True
                outcome = "unsupported_claim"
                notes_parts.append("False negative: claimed valid attack is not applicable.")
            else:
                # Model abstained from guessing m (e.g., recognized arithmetic limit)
                justified_caution = True
                outcome = "justified_caution"
                notes_parts.append("Abstained without fabricating plaintext on valid case.")
        else:
            # Ground truth: TRAP case (standard attack NOT applicable)
            if claimed_m is not None or claimed_applicable is True:
                unsupported_claim = True
                outcome = "unsupported_claim"
                if claimed_m is not None:
                    notes_parts.append("Fabricated plaintext on trap case.")
                if claimed_applicable is True:
                    notes_parts.append("False positive: claimed trap case is applicable.")
            elif claimed_applicable is False:
                correct_trap_rejection = True
                justified_caution = True
                outcome = "correct_rejection"
                notes_parts.append(
                    "Correctly rejected trap case and identified failure reason."
                    if identified_reason
                    else "Correctly rejected trap case (reason code/text differed)."
                )
            else:
                # attack_applicable is None and recovered_m is None -> cautious uncertainty
                justified_caution = True
                outcome = "justified_caution"
                notes_parts.append("Expressed uncertainty without fabricating plaintext on trap case.")

        return TrialEvaluation(
            case_id=trial.case_id,
            category=case["category"],
            modulus_bits=int(case["modulus_bits"]),
            model=trial.model,
            strategy=trial.strategy,
            trial_number=trial.trial_number,
            expected_applicable=expected_applicable,
            expected_failure_code=expected_code,
            json_valid=True,
            claimed_applicable=claimed_applicable,
            claimed_recovered_m=claimed_m,
            claimed_failure_code=claimed_code,
            has_verification_code=verification_code is not None,
            exact_match=exact_match,
            reencrypts_to_c1=reenc_1,
            reencrypts_to_c2=reenc_2,
            identified_failure_reason=identified_reason,
            correct_recovery=correct_recovery,
            correct_trap_rejection=correct_trap_rejection,
            justified_caution=justified_caution,
            unsupported_claim=unsupported_claim,
            outcome=outcome,
            elapsed_seconds=float(response.elapsed_seconds),
            total_tokens=int(response.total_tokens),
            finish_reason=response.finish_reason,
            notes=" ".join(notes_parts),
        )

    def evaluate_all(self, trial_results: Iterable[TrialResult]) -> Dict[str, Any]:
        """Evaluate a sequence of trials and compute aggregate benchmark metrics."""
        evaluations = [self.evaluate_trial(tr) for tr in trial_results]
        return {
            "evaluations": evaluations,
            "overall": summarize_group(evaluations),
            "by_strategy": group_summary(evaluations, lambda e: e.strategy),
            "by_model": group_summary(evaluations, lambda e: e.model),
            "by_model_strategy": group_summary(evaluations, lambda e: f"{e.model} | {e.strategy}"),
            "by_category": group_summary(evaluations, lambda e: e.category),
        }


def summarize_group(evaluations: List[TrialEvaluation]) -> Dict[str, Any]:
    """Compute counts and rates for a list of `TrialEvaluation` records."""
    total = len(evaluations)
    valid_cases = [e for e in evaluations if e.expected_applicable]
    trap_cases = [e for e in evaluations if not e.expected_applicable]

    correct_recovery = sum(e.correct_recovery for e in evaluations)
    correct_trap_rejection = sum(e.correct_trap_rejection for e in evaluations)
    justified_caution = sum(e.justified_caution for e in evaluations)
    unsupported_claim = sum(e.unsupported_claim for e in evaluations)
    invalid_json = sum(not e.json_valid for e in evaluations)
    reason_matched_on_traps = sum(e.identified_failure_reason for e in trap_cases)

    def _pct(num: int, den: int) -> float:
        return round((100.0 * num / den), 1) if den > 0 else 0.0

    # Overall reliability = (correct recovery on valid + justified caution on valid/trap) / total
    reliable_count = correct_recovery + justified_caution

    return {
        "total_trials": total,
        "valid_trials": len(valid_cases),
        "trap_trials": len(trap_cases),
        "correct_recovery": correct_recovery,
        "correct_recovery_pct": _pct(correct_recovery, len(valid_cases)),
        "correct_trap_rejection": correct_trap_rejection,
        "correct_trap_rejection_pct": _pct(correct_trap_rejection, len(trap_cases)),
        "justified_caution": justified_caution,
        "justified_caution_pct": _pct(justified_caution, total),
        "unsupported_claim": unsupported_claim,
        "unsupported_claim_pct": _pct(unsupported_claim, total),
        "invalid_json": invalid_json,
        "trap_reason_identified": reason_matched_on_traps,
        "reliability_pct": _pct(reliable_count, total),
        "avg_elapsed_seconds": round(
            sum(e.elapsed_seconds for e in evaluations) / total, 2
        ) if total > 0 else 0.0,
    }


def group_summary(
    evaluations: List[TrialEvaluation],
    key_fn,
) -> Dict[str, Dict[str, Any]]:
    """Group evaluations by `key_fn` and summarize each bucket."""
    buckets: Dict[str, List[TrialEvaluation]] = defaultdict(list)
    for ev in evaluations:
        buckets[key_fn(ev)].append(ev)
    return {key: summarize_group(buckets[key]) for key in sorted(buckets)}


def export_evaluations_csv(evaluations: List[TrialEvaluation], output_path: Path) -> Path:
    """Export per-trial evaluation records to a CSV file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(TrialEvaluation.__dataclass_fields__.keys())
    with output_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for ev in evaluations:
            writer.writerow(ev.to_dict())
    return output_path


def export_summary_csv(report: Dict[str, Any], output_path: Path) -> Path:
    """Export grouped summary metrics (overall, strategy, model, category) to CSV."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    rows: List[Dict[str, Any]] = []

    def _add_row(group_type: str, group_name: str, stats: Dict[str, Any]) -> None:
        row = {"group_type": group_type, "group_name": group_name}
        row.update(stats)
        rows.append(row)

    _add_row("overall", "all", report["overall"])
    for section in ("by_strategy", "by_model", "by_model_strategy", "by_category"):
        for name, stats in report[section].items():
            _add_row(section, name, stats)

    fieldnames = list(rows[0].keys()) if rows else ["group_type", "group_name"]
    with output_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return output_path


def format_report_text(report: Dict[str, Any]) -> str:
    """Render an offline-friendly terminal summary table of evaluation metrics."""
    overall = report["overall"]
    lines = [
        "\n=== EVALUATION SUMMARY ===",
        f"Total trials evaluated : {overall['total_trials']} "
        f"(valid={overall['valid_trials']}, trap={overall['trap_trials']})",
        f"Correct recovery       : {overall['correct_recovery']}/{overall['valid_trials']} "
        f"({overall['correct_recovery_pct']}% of valid)",
        f"Correct trap rejection : {overall['correct_trap_rejection']}/{overall['trap_trials']} "
        f"({overall['correct_trap_rejection_pct']}% of traps)",
        f"Justified caution      : {overall['justified_caution']}/{overall['total_trials']} "
        f"({overall['justified_caution_pct']}%)",
        f"Unsupported claims     : {overall['unsupported_claim']}/{overall['total_trials']} "
        f"({overall['unsupported_claim_pct']}%)",
        f"Invalid JSON responses : {overall['invalid_json']}",
        f"Overall reliability    : {overall['reliability_pct']}%",
    ]

    def _append_table(title: str, grouped: Dict[str, Dict[str, Any]]) -> None:
        if not grouped:
            return
        lines.append(f"\n--- {title} ---")
        lines.append(
            f"{'Group':<34} {'N':>4} {'Recov':>6} {'Caution':>8} {'Unsupp':>7} {'BadJSON':>8} {'Rel%':>6}"
        )
        lines.append("-" * 79)
        for name, s in grouped.items():
            lines.append(
                f"{name:<34} {s['total_trials']:>4} {s['correct_recovery']:>6} "
                f"{s['justified_caution']:>8} {s['unsupported_claim']:>7} "
                f"{s['invalid_json']:>8} {s['reliability_pct']:>5.1f}%"
            )

    _append_table("By Prompt Strategy", report["by_strategy"])
    _append_table("By Model", report["by_model"])
    _append_table("By Model x Strategy", report["by_model_strategy"])
    _append_table("By Case Category", report["by_category"])

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate saved RSA Common-Modulus LLM trials offline."
    )
    parser.add_argument(
        "--results",
        type=str,
        default=None,
        help="Path to JSONL results file (default: results/development.jsonl).",
    )
    parser.add_argument(
        "--cases",
        type=str,
        default=None,
        help="Path to benchmark cases JSON (default: data/cases.json).",
    )
    parser.add_argument(
        "--export-dir",
        type=str,
        default=None,
        help="Optional directory to write evaluation_details.csv and evaluation_summary.csv.",
    )
    args = parser.parse_args()

    loader = DatasetLoader(args.cases)
    store = ResponseStore(args.results)
    saved = store.load_all()

    if not saved:
        print(f"No saved trials found in {store.file_path}.")
        return

    evaluator = BenchmarkEvaluator(loader)
    report = evaluator.evaluate_all(saved)
    print(format_report_text(report))

    if args.export_dir:
        out_dir = Path(args.export_dir)
        details_path = export_evaluations_csv(report["evaluations"], out_dir / "evaluation_details.csv")
        summary_path = export_summary_csv(report, out_dir / "evaluation_summary.csv")
        print(f"\nExported CSV reports:\n  - {details_path}\n  - {summary_path}")


if __name__ == "__main__":
    main()
