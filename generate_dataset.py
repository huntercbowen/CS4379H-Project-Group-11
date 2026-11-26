"""Deterministic 55-case RSA Common-Modulus benchmark dataset generator.

Group 11 (Quanta Correspondent) — CS 4379H Cryptography
Generates 55 seeded RSA test cases (seed=4379) using realistic public exponent pairs
(e.g., 17, 257, 65537, 65539) and ASCII-encoded plaintexts on valid cases.

Categories (55 total):
  - valid_small             (10): 24-32 bit N, standard small coprime exponents
  - valid_large             (15): 128/256/512 bit N, ASCII messages (tests big-int math)
  - trap_non_coprime        (10): gcd(e1, e2) > 1
  - trap_different_messages (10): m1 != m2 (passes arithmetic preconditions, fails re-encryption)
  - trap_broken_setup       (10): 4x N1 != N2, 3x c >= N, 3x gcd(c_neg, N) > 1

Usage:
    python generate_dataset.py --output data/cases.json --verify
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import random
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from rsa_math import ascii_to_int, common_modulus_attack, extended_gcd, generate_prime

DEFAULT_SEED = 4379

# Realistic RSA public-exponent pairs commonly seen in textbook/CTF implementations
SMALL_EXPONENT_PAIRS = [
    (3, 5),
    (5, 7),
    (7, 11),
    (11, 13),
    (13, 17),
    (17, 23),
    (17, 29),
    (19, 31),
    (23, 37),
    (17, 41),
]

STANDARD_EXPONENT_PAIRS = [
    (17, 65537),
    (3, 65537),
    (5, 65537),
    (7, 65537),
    (257, 65537),
    (65537, 65539),
    (17, 257),
    (65537, 65543),
    (257, 65539),
    (13, 65537),
]


def _generate_modulus(n_bits: int, rng: random.Random) -> Tuple[int, int, int, int]:
    """Generate distinct primes p, q and return (N, phi(N), p, q)."""
    p_bits = n_bits // 2
    q_bits = n_bits - p_bits
    while True:
        p = generate_prime(p_bits, rng)
        q = generate_prime(q_bits, rng)
        if p != q:
            return p * q, (p - 1) * (q - 1), p, q


def _pick_realistic_exponents(
    phi: int,
    rng: random.Random,
    prefer_small: bool = False,
) -> Tuple[int, int]:
    """Select realistic coprime RSA public exponents valid for phi(N)."""
    pool = list(SMALL_EXPONENT_PAIRS if prefer_small else STANDARD_EXPONENT_PAIRS)
    rng.shuffle(pool)
    for e1, e2 in pool:
        if e1 < phi and e2 < phi and math.gcd(e1, phi) == 1 and math.gcd(e2, phi) == 1 and math.gcd(e1, e2) == 1:
            return (e1, e2) if rng.random() < 0.5 else (e2, e1)

    # Fallback if phi happened to share a factor with every pair in the pool
    while True:
        e1 = rng.randrange(17, min(65537, phi - 1)) | 1
        e2 = rng.randrange(17, min(65537, phi - 1)) | 1
        if e1 != e2 and math.gcd(e1, phi) == 1 and math.gcd(e2, phi) == 1 and math.gcd(e1, e2) == 1:
            return e1, e2


def _pick_non_coprime_exponents(phi: int, rng: random.Random) -> Tuple[int, int, int]:
    """Select valid RSA exponents e1, e2 (both coprime to phi) with gcd(e1, e2) = g > 1."""
    factors = [3, 5, 7, 11, 13]
    rng.shuffle(factors)
    for g in factors:
        if math.gcd(g, phi) != 1:
            continue
        for _ in range(200):
            k1 = rng.randrange(3, 35) | 1
            k2 = rng.randrange(3, 35) | 1
            if k1 != k2 and math.gcd(k1, k2) == 1:
                e1, e2 = g * k1, g * k2
                if e1 < phi and e2 < phi and math.gcd(e1, phi) == 1 and math.gcd(e2, phi) == 1:
                    return e1, e2, g
    raise RuntimeError("Failed to find non-coprime RSA exponents.")


def _pick_plaintext(n: int, rng: random.Random) -> int:
    """Pick a random plaintext integer m in [100, N - 2] coprime to N."""
    upper = max(102, n - 2)
    while True:
        m = rng.randrange(100, upper)
        if math.gcd(m, n) == 1:
            return m


def _make_record(
    case_id: str,
    category: str,
    n_bits: int,
    n1: int,
    n2: int,
    e1: int,
    e2: int,
    c1: int,
    c2: int,
    attack_applicable: bool,
    expected_m: Optional[int],
    expected_text: Optional[str],
    expected_failure_code: str,
    note: str,
) -> Dict[str, Any]:
    """Format one test case using base-10 strings to preserve arbitrary-precision ints."""
    return {
        "case_id": case_id,
        "category": category,
        "modulus_bits": n_bits,
        "n1": str(n1),
        "n2": str(n2),
        "e1": str(e1),
        "e2": str(e2),
        "c1": str(c1),
        "c2": str(c2),
        "attack_applicable": attack_applicable,
        "expected_m": str(expected_m) if expected_m is not None else None,
        "expected_text": expected_text,
        "expected_failure_code": expected_failure_code,
        "note": note,
    }


def build_dataset(seed: int = DEFAULT_SEED) -> Dict[str, Any]:
    """Build all 55 deterministic RSA Common-Modulus benchmark cases."""
    rng = random.Random(seed)
    cases: List[Dict[str, Any]] = []
    idx = 1

    # 1. valid_small (10 cases, 24-32 bit N, short 2-3 char ASCII plaintexts)
    small_specs = [
        (24, "ok"),
        (24, "hi"),
        (24, "k1"),
        (26, "rsa"),
        (26, "mod"),
        (28, "key"),
        (28, "tx1"),
        (30, "gcd"),
        (32, "cs4"),
        (32, "m10"),
    ]
    for bits, msg in small_specs:
        n, phi, _, _ = _generate_modulus(bits, rng)
        e1, e2 = _pick_realistic_exponents(phi, rng, prefer_small=True)
        m = ascii_to_int(msg)
        assert m < n and math.gcd(m, n) == 1
        cases.append(
            _make_record(
                case_id=f"CASE-{idx:03d}",
                category="valid_small",
                n_bits=n.bit_length(),
                n1=n,
                n2=n,
                e1=e1,
                e2=e2,
                c1=pow(m, e1, n),
                c2=pow(m, e2, n),
                attack_applicable=True,
                expected_m=m,
                expected_text=msg,
                expected_failure_code="ok",
                note=f"valid {n.bit_length()}-bit",
            )
        )
        idx += 1

    # 2. valid_large (15 cases: 5x 128-bit, 5x 256-bit, 5x 512-bit with ASCII messages)
    large_specs = [
        (128, "txst_rsa_11"),
        (128, "bezout_key_12"),
        (128, "cs4379_msg_13"),
        (128, "common_mod_14"),
        (128, "flag_eval_15"),
        (256, "txst_cs4379h_case_16"),
        (256, "common_modulus_test_17"),
        (256, "verify_reencrypt_18"),
        (256, "aicrypto_bench_19"),
        (256, "quanta_group11_20"),
        (512, "flag{cs4379h_common_modulus_21}"),
        (512, "flag{verify_bezout_before_trust_22}"),
        (512, "flag{rsa_512bit_arithmetic_wall_23}"),
        (512, "flag{shared_modulus_leaks_msg_24}"),
        (512, "flag{quanta_correspondent_final_25}"),
    ]
    for bits, msg in large_specs:
        n, phi, _, _ = _generate_modulus(bits, rng)
        e1, e2 = _pick_realistic_exponents(phi, rng, prefer_small=False)
        m = ascii_to_int(msg)
        assert m < n and math.gcd(m, n) == 1
        cases.append(
            _make_record(
                case_id=f"CASE-{idx:03d}",
                category="valid_large",
                n_bits=n.bit_length(),
                n1=n,
                n2=n,
                e1=e1,
                e2=e2,
                c1=pow(m, e1, n),
                c2=pow(m, e2, n),
                attack_applicable=True,
                expected_m=m,
                expected_text=msg,
                expected_failure_code="ok",
                note=f"valid {n.bit_length()}-bit",
            )
        )
        idx += 1

    # 3. trap_non_coprime (10 cases: gcd(e1, e2) > 1)
    for bits in [24, 28, 32, 32, 64, 64, 128, 128, 256, 256]:
        n, phi, _, _ = _generate_modulus(bits, rng)
        e1, e2, g = _pick_non_coprime_exponents(phi, rng)
        m = _pick_plaintext(n, rng)
        cases.append(
            _make_record(
                case_id=f"CASE-{idx:03d}",
                category="trap_non_coprime",
                n_bits=n.bit_length(),
                n1=n,
                n2=n,
                e1=e1,
                e2=e2,
                c1=pow(m, e1, n),
                c2=pow(m, e2, n),
                attack_applicable=False,
                expected_m=None,
                expected_text=None,
                expected_failure_code="non_coprime_exponents",
                note=f"gcd(e1,e2)={g}",
            )
        )
        idx += 1

    # 4. trap_different_messages (10 cases: m1 != m2)
    for bits in [24, 28, 32, 32, 64, 64, 128, 128, 256, 256]:
        n, phi, _, _ = _generate_modulus(bits, rng)
        e1, e2 = _pick_realistic_exponents(phi, rng, prefer_small=(bits <= 32))
        m1 = _pick_plaintext(n, rng)
        m2 = _pick_plaintext(n, rng)
        while m2 == m1:
            m2 = _pick_plaintext(n, rng)
        cases.append(
            _make_record(
                case_id=f"CASE-{idx:03d}",
                category="trap_different_messages",
                n_bits=n.bit_length(),
                n1=n,
                n2=n,
                e1=e1,
                e2=e2,
                c1=pow(m1, e1, n),
                c2=pow(m2, e2, n),
                attack_applicable=False,
                expected_m=None,
                expected_text=None,
                expected_failure_code="different_messages",
                note="m1 != m2",
            )
        )
        idx += 1

    # 5a. trap_broken_setup: distinct moduli (4 cases)
    for bits in [28, 32, 128, 256]:
        n1, phi1, _, _ = _generate_modulus(bits, rng)
        n2, phi2, _, _ = _generate_modulus(bits, rng)
        while n2 == n1:
            n2, phi2, _, _ = _generate_modulus(bits, rng)
        # Pick coprime exponents valid for both moduli
        e1, e2 = 17, 65537
        if bits <= 32 or math.gcd(e1, phi1) != 1 or math.gcd(e2, phi2) != 1:
            while True:
                e1 = rng.randrange(17, 500) | 1
                e2 = rng.randrange(17, 500) | 1
                if (
                    e1 != e2
                    and math.gcd(e1, phi1) == 1
                    and math.gcd(e2, phi2) == 1
                    and math.gcd(e1, e2) == 1
                ):
                    break
        m = _pick_plaintext(min(n1, n2), rng)
        cases.append(
            _make_record(
                case_id=f"CASE-{idx:03d}",
                category="trap_broken_setup",
                n_bits=n1.bit_length(),
                n1=n1,
                n2=n2,
                e1=e1,
                e2=e2,
                c1=pow(m, e1, n1),
                c2=pow(m, e2, n2),
                attack_applicable=False,
                expected_m=None,
                expected_text=None,
                expected_failure_code="distinct_moduli",
                note="N1 != N2",
            )
        )
        idx += 1

    # 5b. trap_broken_setup: ciphertext out of range c >= N (3 cases)
    for i, bits in enumerate([28, 64, 128]):
        n, phi, _, _ = _generate_modulus(bits, rng)
        e1, e2 = _pick_realistic_exponents(phi, rng, prefer_small=(bits <= 32))
        m = _pick_plaintext(n, rng)
        c1, c2 = pow(m, e1, n), pow(m, e2, n)
        if i % 2 == 0:
            c1 += n
            bad = "c1 >= N"
        else:
            c2 += n
            bad = "c2 >= N"
        cases.append(
            _make_record(
                case_id=f"CASE-{idx:03d}",
                category="trap_broken_setup",
                n_bits=n.bit_length(),
                n1=n,
                n2=n,
                e1=e1,
                e2=e2,
                c1=c1,
                c2=c2,
                attack_applicable=False,
                expected_m=None,
                expected_text=None,
                expected_failure_code="ciphertext_out_of_range",
                note=bad,
            )
        )
        idx += 1

    # 5c. trap_broken_setup: non-invertible ciphertext gcd(c_neg, N) > 1 (3 cases)
    for bits in [28, 64, 128]:
        n, phi, p, q = _generate_modulus(bits, rng)
        e1, e2 = _pick_realistic_exponents(phi, rng, prefer_small=(bits <= 32))
        m = rng.randrange(2, q - 1) * p  # gcd(m, N) = p => gcd(c1, N) = gcd(c2, N) = p
        _, s1, s2 = extended_gcd(e1, e2)
        neg = "s1" if s1 < 0 else "s2"
        cases.append(
            _make_record(
                case_id=f"CASE-{idx:03d}",
                category="trap_broken_setup",
                n_bits=n.bit_length(),
                n1=n,
                n2=n,
                e1=e1,
                e2=e2,
                c1=pow(m, e1, n),
                c2=pow(m, e2, n),
                attack_applicable=False,
                expected_m=None,
                expected_text=None,
                expected_failure_code="non_invertible_ciphertext",
                note=f"gcd(c,N) > 1 ({neg} < 0)",
            )
        )
        idx += 1

    canonical = json.dumps(cases, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "metadata": {
            "seed": seed,
            "total_cases": len(cases),
            "category_counts": dict(Counter(c["category"] for c in cases)),
            "cases_sha256": hashlib.sha256(canonical).hexdigest(),
        },
        "cases": cases,
    }


def verify_dataset(dataset: Dict[str, Any]) -> Tuple[int, int]:
    """Verify all generated cases against the reference solver."""
    cases = dataset["cases"]
    for case in cases:
        res = common_modulus_attack(
            case["n1"], case["n2"], case["e1"], case["e2"], case["c1"], case["c2"]
        )
        assert res.applicable == case["attack_applicable"], f"{case['case_id']}: applicability mismatch"
        assert res.failure_code == case["expected_failure_code"], f"{case['case_id']}: code mismatch"
        if case["attack_applicable"]:
            assert str(res.recovered_m) == case["expected_m"], f"{case['case_id']}: m mismatch"
            assert res.recovered_text == case["expected_text"], f"{case['case_id']}: text mismatch"
            assert res.reencryption_verified is True
        else:
            assert res.recovered_m is None
    return len(cases), len(cases)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate deterministic RSA Common-Modulus test cases.")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--output", type=str, default=os.path.join("data", "cases.json"))
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()

    dataset = build_dataset(seed=args.seed)
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(dataset, fh, indent=2)

    meta = dataset["metadata"]
    print(f"Wrote {meta['total_cases']} cases -> {out_path} (seed={meta['seed']}, sha256={meta['cases_sha256'][:12]})")
    for cat, count in meta["category_counts"].items():
        print(f"  {cat:<24s}: {count}")

    if args.verify:
        passed, total = verify_dataset(dataset)
        print(f"Verified {passed}/{total} cases against reference solver.")


if __name__ == "__main__":
    main()
