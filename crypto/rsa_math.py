"""RSA number-theory primitives, Common-Modulus Attack solver, and LLM verifier.

Group 11 (Quanta Correspondent) — CS 4379H Cryptography
Reference implementation for benchmarking LLM reasoning and precondition checking
on RSA Common-Modulus Attacks (inspired by AICrypto, Wang et al., arXiv:2507.09580v6).

Attack overview:
  Given two RSA ciphertexts sharing the same modulus N = p * q and encrypting the
  same plaintext m (0 <= m < N) under coprime exponents gcd(e1, e2) = 1:
      c1 = m^e1 mod N,   c2 = m^e2 mod N
  By Bezout's identity, there exist integers s1, s2 with s1*e1 + s2*e2 = 1, so:
      m = (c1^s1 * c2^s2) mod N

Standard library only (no external packages required).
"""

from __future__ import annotations

import math
import random
from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional, Tuple, Union

IntLike = Union[int, str]


@dataclass(frozen=True)
class AttackResult:
    """Output returned by the reference RSA Common-Modulus solver."""

    applicable: bool
    recovered_m: Optional[int]
    recovered_text: Optional[str]
    failure_code: str
    failure_reason: str
    gcd_e1_e2: int
    bezout_s1: Optional[int]
    bezout_s2: Optional[int]
    reencryption_verified: bool

    def to_dict(self) -> Dict[str, Any]:
        """Serialize big integers as base-10 strings for safe JSON export."""
        data = asdict(self)
        data["recovered_m"] = str(self.recovered_m) if self.recovered_m is not None else None
        data["gcd_e1_e2"] = str(self.gcd_e1_e2)
        data["bezout_s1"] = str(self.bezout_s1) if self.bezout_s1 is not None else None
        data["bezout_s2"] = str(self.bezout_s2) if self.bezout_s2 is not None else None
        return data


def _to_int(value: IntLike) -> int:
    """Convert an int or base-10 numeric string into a Python int."""
    if isinstance(value, bool):
        raise TypeError("Boolean values are not valid RSA integers.")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value.strip())
    raise TypeError(f"Expected int or numeric str, got {type(value).__name__}.")


def ascii_to_int(text: str) -> int:
    """Encode an ASCII string to a big-endian positive integer."""
    return int.from_bytes(text.encode("ascii"), "big")


def int_to_ascii(value: int) -> Optional[str]:
    """Decode a big-endian integer back to printable ASCII, or None if not printable."""
    if value <= 0:
        return None
    byte_len = (value.bit_length() + 7) // 8
    raw = value.to_bytes(byte_len, "big")
    try:
        decoded = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    return decoded if all(32 <= ord(ch) <= 126 for ch in decoded) else None


def is_probable_prime(n: int, rng: random.Random, rounds: int = 40) -> bool:
    """Deterministic-seed Miller-Rabin primality test (error bound <= 4^-40)."""
    if n < 2:
        return False

    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False

    # Write n - 1 = 2^r * d with d odd
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(rounds):
        a = rng.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int, rng: random.Random) -> int:
    """Generate a probable prime with exact bit length `bits`."""
    if bits < 8:
        raise ValueError("Prime bit length must be at least 8.")
    while True:
        candidate = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate, rng):
            return candidate


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Iterative Extended Euclidean Algorithm returning (g, x, y) with a*x + b*y = g."""
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t

    if old_r < 0:
        return -old_r, -old_s, -old_t
    return old_r, old_s, old_t


def mod_inverse(a: int, modulus: int) -> int:
    """Return a^(-1) mod modulus, or raise ValueError if gcd(a, modulus) != 1."""
    if modulus <= 1:
        raise ValueError(f"Modulus must be > 1, got {modulus}.")
    g, x, _ = extended_gcd(a % modulus, modulus)
    if g != 1:
        raise ValueError(f"No inverse: gcd({a}, {modulus}) = {g}.")
    return x % modulus


def check_preconditions(
    n1: IntLike,
    n2: IntLike,
    e1: IntLike,
    e2: IntLike,
    c1: IntLike,
    c2: IntLike,
) -> Tuple[bool, str, str, int, Optional[int], Optional[int]]:
    """Verify all structural and number-theoretic preconditions before attack."""
    n1_i, n2_i = _to_int(n1), _to_int(n2)
    e1_i, e2_i = _to_int(e1), _to_int(e2)
    c1_i, c2_i = _to_int(c1), _to_int(c2)

    if n1_i <= 2 or n2_i <= 2:
        return False, "invalid_modulus", "Modulus must be > 2.", 0, None, None
    if n1_i != n2_i:
        return False, "distinct_moduli", "N1 != N2; attack requires a shared modulus.", math.gcd(e1_i, e2_i), None, None

    n = n1_i
    if e1_i <= 1 or e2_i <= 1:
        return False, "invalid_exponents", "Exponents e1 and e2 must be > 1.", math.gcd(e1_i, e2_i), None, None
    if e1_i == e2_i:
        return False, "identical_exponents", "e1 == e2, so gcd(e1, e2) > 1.", e1_i, None, None
    if not (0 <= c1_i < n) or not (0 <= c2_i < n):
        return False, "ciphertext_out_of_range", "Ciphertexts must satisfy 0 <= c < N.", math.gcd(e1_i, e2_i), None, None

    g, s1, s2 = extended_gcd(e1_i, e2_i)
    if g != 1:
        return False, "non_coprime_exponents", f"gcd(e1, e2) = {g} != 1; Bezout yields m^{g} mod N.", g, s1, s2

    # Exactly one of s1, s2 is negative; its base ciphertext must be invertible mod N
    if s1 < 0 and math.gcd(c1_i, n) != 1:
        return (
            False,
            "non_invertible_ciphertext",
            f"s1 = {s1} < 0 requires c1^(-1) mod N, but gcd(c1, N) = {math.gcd(c1_i, n)} > 1 (leaks a factor of N).",
            g,
            s1,
            s2,
        )
    if s2 < 0 and math.gcd(c2_i, n) != 1:
        return (
            False,
            "non_invertible_ciphertext",
            f"s2 = {s2} < 0 requires c2^(-1) mod N, but gcd(c2, N) = {math.gcd(c2_i, n)} > 1 (leaks a factor of N).",
            g,
            s1,
            s2,
        )

    return True, "ok", "Preconditions satisfied.", g, s1, s2


def common_modulus_attack(
    n1: IntLike,
    n2: IntLike,
    e1: IntLike,
    e2: IntLike,
    c1: IntLike,
    c2: IntLike,
) -> AttackResult:
    """Run the RSA Common-Modulus Attack with precondition and re-encryption checks."""
    passed, code, reason, g, s1, s2 = check_preconditions(n1, n2, e1, e2, c1, c2)
    if not passed or s1 is None or s2 is None:
        return AttackResult(
            applicable=False,
            recovered_m=None,
            recovered_text=None,
            failure_code=code,
            failure_reason=reason,
            gcd_e1_e2=g,
            bezout_s1=s1,
            bezout_s2=s2,
            reencryption_verified=False,
        )

    n = _to_int(n1)
    e1_i, e2_i = _to_int(e1), _to_int(e2)
    c1_i, c2_i = _to_int(c1), _to_int(c2)

    part1 = pow(mod_inverse(c1_i, n), -s1, n) if s1 < 0 else pow(c1_i, s1, n)
    part2 = pow(mod_inverse(c2_i, n), -s2, n) if s2 < 0 else pow(c2_i, s2, n)
    candidate_m = (part1 * part2) % n

    # Re-encrypt candidate_m to detect different-plaintext traps (m1 != m2)
    reenc_ok = pow(candidate_m, e1_i, n) == c1_i and pow(candidate_m, e2_i, n) == c2_i
    if not reenc_ok:
        return AttackResult(
            applicable=False,
            recovered_m=None,
            recovered_text=None,
            failure_code="different_messages",
            failure_reason="Candidate m failed re-encryption against c1 and c2 (likely m1 != m2).",
            gcd_e1_e2=g,
            bezout_s1=s1,
            bezout_s2=s2,
            reencryption_verified=False,
        )

    return AttackResult(
        applicable=True,
        recovered_m=candidate_m,
        recovered_text=int_to_ascii(candidate_m),
        failure_code="ok",
        failure_reason="Recovered plaintext verified by re-encryption.",
        gcd_e1_e2=g,
        bezout_s1=s1,
        bezout_s2=s2,
        reencryption_verified=True,
    )


def verify_candidate_plaintext(case: Dict[str, Any], candidate_m: Optional[IntLike]) -> Dict[str, Any]:
    """Verify an LLM-predicted plaintext against ground truth and re-encryption.

    Intended to be imported directly by Member 3's `evaluator.py`.
    """
    if candidate_m is None:
        return {
            "valid_candidate_parsed": False,
            "exact_match": False,
            "reencrypts_to_c1": False,
            "reencrypts_to_c2": False,
        }

    try:
        cand_int = _to_int(candidate_m)
    except (TypeError, ValueError):
        return {
            "valid_candidate_parsed": False,
            "exact_match": False,
            "reencrypts_to_c1": False,
            "reencrypts_to_c2": False,
        }

    n1, n2 = _to_int(case["n1"]), _to_int(case["n2"])
    e1, e2 = _to_int(case["e1"]), _to_int(case["e2"])
    c1, c2 = _to_int(case["c1"]), _to_int(case["c2"])

    reenc_1 = (0 <= cand_int < n1) and (pow(cand_int, e1, n1) == c1)
    reenc_2 = (0 <= cand_int < n2) and (pow(cand_int, e2, n2) == c2)

    expected_m = case.get("expected_m")
    exact_match = (
        bool(case.get("attack_applicable"))
        and expected_m is not None
        and cand_int == _to_int(expected_m)
    )

    return {
        "valid_candidate_parsed": True,
        "exact_match": exact_match,
        "reencrypts_to_c1": reenc_1,
        "reencrypts_to_c2": reenc_2,
    }
