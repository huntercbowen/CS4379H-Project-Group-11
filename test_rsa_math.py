"""Unit tests for rsa_math.py and generate_dataset.py.

Run with:
    python -m unittest -v test_rsa_math.py
"""

from __future__ import annotations

import math
import random
import unittest

from generate_dataset import DEFAULT_SEED, build_dataset, verify_dataset
from rsa_math import (
    ascii_to_int,
    common_modulus_attack,
    extended_gcd,
    generate_prime,
    int_to_ascii,
    is_probable_prime,
    mod_inverse,
    verify_candidate_plaintext,
)


class TestPrimitives(unittest.TestCase):
    def test_extended_gcd(self) -> None:
        for a, b in [(17, 65537), (65537, 65539), (48, 18), (2**127 - 1, 2**89 - 1)]:
            g, x, y = extended_gcd(a, b)
            self.assertEqual(g, math.gcd(a, b))
            self.assertEqual(a * x + b * y, g)

    def test_mod_inverse(self) -> None:
        self.assertEqual((17 * mod_inverse(17, 3120)) % 3120, 1)
        with self.assertRaises(ValueError):
            mod_inverse(6, 15)

    def test_miller_rabin_and_prime_gen(self) -> None:
        rng = random.Random(12345)
        for p in (2, 3, 5, 17, 65537, 104729):
            self.assertTrue(is_probable_prime(p, rng))
        # Includes Carmichael numbers 561 and 1729
        for c in (0, 1, 4, 15, 561, 1729, 104729 * 3):
            self.assertFalse(is_probable_prime(c, rng))
        p64 = generate_prime(64, rng)
        self.assertEqual(p64.bit_length(), 64)
        self.assertTrue(is_probable_prime(p64, rng))

    def test_ascii_roundtrip(self) -> None:
        msg = "flag{cs4379h_test}"
        self.assertEqual(int_to_ascii(ascii_to_int(msg)), msg)


class TestCommonModulusAttack(unittest.TestCase):
    def setUp(self) -> None:
        self.p, self.q = 61, 53
        self.n = self.p * self.q
        self.e1, self.e2 = 17, 23
        self.m = 1234

    def test_valid_recovery(self) -> None:
        c1 = pow(self.m, self.e1, self.n)
        c2 = pow(self.m, self.e2, self.n)
        res = common_modulus_attack(self.n, self.n, self.e1, self.e2, c1, c2)
        self.assertTrue(res.applicable)
        self.assertEqual(res.recovered_m, self.m)
        self.assertTrue(res.reencryption_verified)

    def test_non_coprime_exponents(self) -> None:
        e1, e2 = 7, 77
        res = common_modulus_attack(self.n, self.n, e1, e2, pow(self.m, e1, self.n), pow(self.m, e2, self.n))
        self.assertFalse(res.applicable)
        self.assertEqual(res.failure_code, "non_coprime_exponents")
        self.assertEqual(res.gcd_e1_e2, 7)

    def test_different_messages(self) -> None:
        res = common_modulus_attack(self.n, self.n, self.e1, self.e2, pow(1234, self.e1, self.n), pow(2222, self.e2, self.n))
        self.assertFalse(res.applicable)
        self.assertEqual(res.failure_code, "different_messages")

    def test_distinct_moduli(self) -> None:
        n2 = 67 * 71
        res = common_modulus_attack(self.n, n2, self.e1, self.e2, pow(self.m, self.e1, self.n), pow(self.m, self.e2, n2))
        self.assertFalse(res.applicable)
        self.assertEqual(res.failure_code, "distinct_moduli")

    def test_ciphertext_out_of_range(self) -> None:
        c1 = pow(self.m, self.e1, self.n) + self.n
        c2 = pow(self.m, self.e2, self.n)
        res = common_modulus_attack(self.n, self.n, self.e1, self.e2, c1, c2)
        self.assertFalse(res.applicable)
        self.assertEqual(res.failure_code, "ciphertext_out_of_range")

    def test_non_invertible_ciphertext(self) -> None:
        m_bad = 5 * self.p
        res = common_modulus_attack(self.n, self.n, self.e1, self.e2, pow(m_bad, self.e1, self.n), pow(m_bad, self.e2, self.n))
        self.assertFalse(res.applicable)
        self.assertEqual(res.failure_code, "non_invertible_ciphertext")

    def test_verifier_helper(self) -> None:
        c1, c2 = pow(self.m, self.e1, self.n), pow(self.m, self.e2, self.n)
        case = {
            "n1": str(self.n),
            "n2": str(self.n),
            "e1": str(self.e1),
            "e2": str(self.e2),
            "c1": str(c1),
            "c2": str(c2),
            "attack_applicable": True,
            "expected_m": str(self.m),
        }
        self.assertTrue(verify_candidate_plaintext(case, str(self.m))["exact_match"])
        self.assertFalse(verify_candidate_plaintext(case, self.m + 1)["exact_match"])
        self.assertFalse(verify_candidate_plaintext(case, None)["valid_candidate_parsed"])


class TestDataset(unittest.TestCase):
    def test_deterministic_and_verified(self) -> None:
        ds1 = build_dataset(seed=DEFAULT_SEED)
        ds2 = build_dataset(seed=DEFAULT_SEED)
        self.assertEqual(ds1["metadata"]["cases_sha256"], ds2["metadata"]["cases_sha256"])
        self.assertEqual(ds1["metadata"]["total_cases"], 55)
        passed, total = verify_dataset(ds1)
        self.assertEqual((passed, total), (55, 55))


if __name__ == "__main__":
    unittest.main()
