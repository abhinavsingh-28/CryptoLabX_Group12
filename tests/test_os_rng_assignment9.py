"""
Unit tests for Assignment 9 (OS CSPRNG Data Generation & Statistical Suite).
"""

import os
import sys

# Remove project root from sys.path and evict local 'math/' if cached in sys.modules
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_SHADOWED = [p for p in sys.path if os.path.abspath(p or ".") == PROJECT_ROOT]
for _p in _SHADOWED:
    sys.path.remove(_p)

if "math" in sys.modules and not hasattr(sys.modules["math"], "sqrt"):
    del sys.modules["math"]

import math  # Loads Python's standard library math module
import unittest

sys.path.append(PROJECT_ROOT)

from modern.os_csprng_generator import (
    ONE_MB,
    generate_linux_urandom,
    generate_openssl_rand,
    generate_windows_cng,
)
from analysis.rng_statistical_analysis import evaluate_random_stream


class TestAssignment9OSRNG(unittest.TestCase):
    def test_generators_produce_1mb(self) -> None:
        u_data, _ = generate_linux_urandom(ONE_MB)
        o_data, _ = generate_openssl_rand(ONE_MB)
        w_data, _ = generate_windows_cng(ONE_MB)

        self.assertEqual(len(u_data), ONE_MB)
        self.assertEqual(len(o_data), ONE_MB)
        self.assertEqual(len(w_data), ONE_MB)
        self.assertNotEqual(u_data[:64], o_data[:64])
        self.assertNotEqual(o_data[:64], w_data[:64])

    def test_statistical_metrics_on_csprng_sample(self) -> None:
        # Use 256 KB sample for fast unit test execution
        sample_data, method = generate_windows_cng(262144)
        res = evaluate_random_stream("windows_cng_test", sample_data, method)

        # Entropy of 256 KB uniform random bytes should exceed 7.998 bits/byte
        self.assertGreater(res["byte_stats"]["shannon_entropy"], 7.998)
        # Proportion of 1-bits should be very close to 0.50
        self.assertAlmostEqual(res["bit_stats"]["ones_proportion"], 0.5, delta=0.005)
        # Lag-1 autocorrelation must be near zero
        self.assertAlmostEqual(res["corr_stats"]["lags"][1], 0.0, delta=0.01)

    def test_biased_stream_fails_statistical_tests(self) -> None:
        # A repeating/patterned stream must fail Chi-Square and overall randomness check
        bad_data = (b"\x00\x01\x02\x03" * 32768)
        res = evaluate_random_stream("biased_stream", bad_data, "Deterministic pattern")
        self.assertFalse(res["byte_stats"]["chi2_pass"])
        self.assertFalse(res["overall_pass"])


if __name__ == "__main__":
    unittest.main()