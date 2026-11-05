"""
Assignment 10 - Part A: MT19937 Stream Cipher & 16-Bit Seed Brute-Force Attack
Uses Python's built-in random.Random (MT19937) extracting 8-bit outputs per byte.
"""

import os
import sys

# Prevent local 'math/' folder in CryptoLabX_Group12 from shadowing Python's stdlib 'math'
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_SHADOWED_PATHS = [p for p in sys.path if os.path.abspath(p or ".") == _PROJECT_ROOT]
for _p in _SHADOWED_PATHS:
    sys.path.remove(_p)

import math  # noqa: F401 - Preload stdlib math into sys.modules before repo root is active
import random
import secrets
import string
from typing import Dict, Iterator, Optional, Tuple

sys.path.extend(_SHADOWED_PATHS)


def mt19937_keystream(seed: int, length: int) -> Iterator[int]:
    """
    Step 1: Seed the inbuilt MT19937 PRNG and yield one 8-bit value per byte.
    Uses an isolated random.Random instance so global RNG state is unaffected.
    """
    rng = random.Random(seed)
    for _ in range(length):
        yield rng.getrandbits(8)


def mt19937_crypt(data: bytes, seed: int) -> bytes:
    """
    Step 1: Encrypt or decrypt data by XORing each input byte with one 8-bit
    MT19937 keystream byte. Identical function serves for both operations.
    """
    return bytes(b ^ k for b, k in zip(data, mt19937_keystream(seed, len(data))))


def verify_test_message(test_msg: bytes = b"CryptoLabX_Group12: MT19937 Stream Cipher Test!", seed: int = 4242) -> Dict[str, object]:
    """
    Step 2: Verify encryption and decryption using a test message.
    """
    ciphertext = mt19937_crypt(test_msg, seed)
    decrypted = mt19937_crypt(ciphertext, seed)
    is_valid = decrypted == test_msg
    return {
        "seed": seed,
        "original": test_msg,
        "ciphertext": ciphertext,
        "decrypted": decrypted,
        "verified": is_valid,
    }


def generate_known_suffix_plaintext(known_suffix: bytes = b"A" * 14) -> Tuple[bytes, int]:
    """
    Step 3: Generate plaintext with a random prefix of 5-20 printable ASCII
    characters followed by 14 consecutive 'A' characters.
    """
    prefix_len = secrets.randbelow(16) + 5  # Random integer in [5, 20]
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    prefix = "".join(secrets.choice(alphabet) for _ in range(prefix_len)).encode("ascii")
    return prefix + known_suffix, prefix_len


def encrypt_with_random_16bit_seed(plaintext: bytes) -> Tuple[bytes, int]:
    """
    Step 3: Encrypt the plaintext using a randomly selected 16-bit seed (0 to 65535).
    """
    seed_16bit = secrets.randbits(16)
    ciphertext = mt19937_crypt(plaintext, seed_16bit)
    return ciphertext, seed_16bit


def brute_force_16bit_seed(
    ciphertext: bytes, known_pattern: bytes = b"A" * 14
) -> Dict[str, object]:
    """
    Steps 4 & 5: Given the ciphertext and knowledge of the 14 consecutive 'A'
    characters (location unknown), brute-force all 65,536 seeds and recover
    the matching seed and plaintext.
    """
    matching_seeds = []
    recovered_plaintext: Optional[bytes] = None
    first_match_attempt: Optional[int] = None

    for candidate_seed in range(65536):
        candidate_pt = mt19937_crypt(ciphertext, candidate_seed)
        if known_pattern in candidate_pt:
            matching_seeds.append(candidate_seed)
            if recovered_plaintext is None:
                recovered_plaintext = candidate_pt
                first_match_attempt = candidate_seed + 1

    recovered_seed = matching_seeds[0] if matching_seeds else None

    # Step 5: Independent verification of the recovered seed
    re_decrypted = mt19937_crypt(ciphertext, recovered_seed) if recovered_seed is not None else b""
    pattern_present = known_pattern in re_decrypted

    return {
        "total_seeds_tested": 65536,
        "first_match_attempt": first_match_attempt,
        "matching_seeds": matching_seeds,
        "recovered_seed": recovered_seed,
        "recovered_plaintext": recovered_plaintext,
        "re_decrypted_plaintext": re_decrypted,
        "pattern_present": pattern_present,
    }


def run_part_a_demo() -> None:
    print("=" * 72)
    print("PART A: MT19937 STREAM CIPHER & 16-BIT SEED BRUTE-FORCE ATTACK")
    print("=" * 72)

    # Step 2: Test Message Verification
    test_res = verify_test_message()
    print("\n[Step 1 & 2] Stream Cipher Encryption/Decryption Check:")
    print(f"  Test Seed          : {test_res['seed']}")
    print(f"  Original Message   : {test_res['original'].decode('ascii')}")
    print(f"  Ciphertext (hex)   : {test_res['ciphertext'].hex()}")
    print(f"  Decrypted Message  : {test_res['decrypted'].decode('ascii')}")
    print(f"  Verification Match : {test_res['verified']}")

    # Step 3: Known-Plaintext Setup
    plaintext, prefix_len = generate_known_suffix_plaintext()
    ciphertext, actual_seed = encrypt_with_random_16bit_seed(plaintext)
    print("\n[Step 3] Random Prefix + 14 'A's Plaintext Generation & 16-Bit Encryption:")
    print(f"  Random Prefix Len  : {prefix_len} bytes")
    print(f"  Generated Plaintext: {plaintext.decode('ascii')} ( Total: {len(plaintext)} bytes )")
    print(f"  Actual 16-bit Seed : {actual_seed} (0x{actual_seed:04x})")
    print(f"  Ciphertext (hex)   : {ciphertext.hex()}")

    # Steps 4 & 5: Brute-Force Seed Recovery & Verification
    bf_res = brute_force_16bit_seed(ciphertext, known_pattern=b"A" * 14)
    full_match = (
        bf_res["recovered_seed"] == actual_seed
        and bf_res["re_decrypted_plaintext"] == plaintext
        and bf_res["pattern_present"]
    )
    print("\n[Step 4 & 5] 16-Bit Seed Brute-Force Attack & Verification:")
    print(f"  Total Seeds Tested : {bf_res['total_seeds_tested']} (0 to 65,535)")
    print(f"  Found at Attempt   : {bf_res['first_match_attempt']}")
    print(f"  Matching Seed(s)   : {bf_res['matching_seeds']}")
    print(f"  Recovered Seed     : {bf_res['recovered_seed']} (0x{bf_res['recovered_seed']:04x})")
    print(f"  Recovered Plaintext: {bf_res['recovered_plaintext'].decode('ascii', errors='replace')}")
    print(f"  Contains 14 'A's   : {bf_res['pattern_present']}")
    print(f"  Full Verification  : {'SUCCESS' if full_match else 'FAILED'}")


if __name__ == "__main__":
    run_part_a_demo()