"""
Unit tests for Assignment 10 (Part A & Part B).
"""

import os
import sys

# Append project root to the end of sys.path so stdlib 'math' is loaded first
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

from modern.mt19937_cipher import (
    brute_force_16bit_seed,
    generate_known_suffix_plaintext,
    mt19937_crypt,
    verify_test_message,
)
from attacks.mt19937_token_attack import (
    predict_reset_token_timestamp,
    simulate_password_reset_token,
)
import unittest


class TestAssignment10MT19937(unittest.TestCase):
    def test_symmetric_encryption_decryption(self) -> None:
        res = verify_test_message(b"Test message 12345", seed=9999)
        self.assertTrue(res["verified"])
        self.assertEqual(res["original"], res["decrypted"])
        self.assertNotEqual(res["original"], res["ciphertext"])

    def test_16bit_seed_recovery(self) -> None:
        pt, prefix_len = generate_known_suffix_plaintext()
        self.assertGreaterEqual(prefix_len, 5)
        self.assertLessEqual(prefix_len, 20)
        self.assertTrue(pt.endswith(b"A" * 14))

        known_seed = 48123
        ct = mt19937_crypt(pt, known_seed)
        bf = brute_force_16bit_seed(ct, known_pattern=b"A" * 14)

        self.assertEqual(bf["recovered_seed"], known_seed)
        self.assertEqual(bf["re_decrypted_plaintext"], pt)
        self.assertTrue(bf["pattern_present"])

    def test_predictable_token_recovery(self) -> None:
        fixed_ts = 1762389900
        ts, token_bytes, token_hex = simulate_password_reset_token(custom_timestamp=fixed_ts)
        self.assertEqual(len(token_bytes), 16)
        self.assertEqual(len(token_hex), 32)

        res = predict_reset_token_timestamp(token_hex, reference_time=ts + 42, window_seconds=300)
        self.assertEqual(res["timestamps_tested"], 601)
        self.assertEqual(res["recovered_timestamp"], fixed_ts)
        self.assertTrue(res["verified"])


if __name__ == "__main__":
    unittest.main()