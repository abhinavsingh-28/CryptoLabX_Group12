"""
Assignment 9 - Tasks 2 & 3: Statistical Evaluation of OS & Cryptographic RNGs
Analyzes byte-frequency distributions, bit distributions, repeated patterns,
serial correlations, and applies formal statistical hypothesis tests (alpha = 0.01).
"""

import os
import sys

# Guard against local 'math/' directory shadowing Python's stdlib 'math'
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_SHADOWED = [p for p in sys.path if os.path.abspath(p or ".") == _PROJECT_ROOT]
for _p in _SHADOWED:
    sys.path.remove(_p)

import math
from collections import Counter
from typing import Dict, List

sys.path.extend(_SHADOWED)

# Lookup table for number of set bits (1s) in each byte (0..255)
_POPCOUNT_TABLE = [bin(i).count("1") for i in range(256)]


def chi_square_p_value(chi2_stat: float, df: int = 255) -> float:
    """
    Computes the upper-tail p-value P(X >= chi2_stat) for a Chi-Square
    distribution with `df` degrees of freedom using the accurate
    Wilson-Hilferty cube-root normal transformation.
    """
    if chi2_stat <= 0:
        return 1.0
    k = float(df)
    z = ((chi2_stat / k) ** (1.0 / 3.0) - (1.0 - 2.0 / (9.0 * k))) / math.sqrt(2.0 / (9.0 * k))
    # Upper tail of standard normal N(0, 1)
    return 0.5 * math.erfc(z / math.sqrt(2.0))


def analyze_byte_distribution(data: bytes) -> Dict[str, float]:
    """
    Task 2 & 3: Byte-frequency distribution, Shannon entropy (bits/byte),
    and Pearson's Chi-Square goodness-of-fit test across 256 byte values.
    """
    n = len(data)
    counts = Counter(data)
    freq_list = [counts.get(b, 0) for b in range(256)]
    expected = n / 256.0

    min_count = min(freq_list)
    max_count = max(freq_list)
    mean_count = expected
    variance = sum((c - expected) ** 2 for c in freq_list) / 256.0
    std_dev = math.sqrt(variance)

    # Chi-Square test statistic: sum((O_i - E)^2 / E)
    chi2_stat = sum(((c - expected) ** 2) / expected for c in freq_list)
    p_val_chi2 = chi_square_p_value(chi2_stat, df=255)

    # Shannon Entropy H(X) = -sum(p_i * log2(p_i))
    shannon_entropy = -sum(
        (c / n) * math.log2(c / n) for c in freq_list if c > 0
    )

    return {
        "total_bytes": n,
        "expected_per_byte": expected,
        "min_byte_count": min_count,
        "max_byte_count": max_count,
        "std_dev_byte_count": std_dev,
        "shannon_entropy": shannon_entropy,
        "chi2_statistic": chi2_stat,
        "chi2_df": 255,
        "chi2_p_value": p_val_chi2,
        "chi2_pass": p_val_chi2 >= 0.01,
    }


def analyze_bit_distribution(data: bytes) -> Dict[str, float]:
    """
    Task 2 & 3: Bit distribution (0s vs 1s) and NIST SP 800-22 Frequency
    (Monobit) Test across all 8 * N bits.
    """
    total_bits = len(data) * 8
    counts = Counter(data)
    ones = sum(counts[b] * _POPCOUNT_TABLE[b] for b in counts)
    zeros = total_bits - ones

    prop_ones = ones / total_bits
    # S_n = (# of 1s) - (# of 0s) = 2 * ones - total_bits
    s_n = 2 * ones - total_bits
    s_obs = abs(s_n) / math.sqrt(total_bits)
    p_val_monobit = math.erfc(s_obs / math.sqrt(2.0))

    return {
        "total_bits": total_bits,
        "ones_count": ones,
        "zeros_count": zeros,
        "ones_proportion": prop_ones,
        "monobit_s_obs": s_obs,
        "monobit_p_value": p_val_monobit,
        "monobit_pass": p_val_monobit >= 0.01,
    }


def analyze_patterns_and_runs(data: bytes, bit_sample_bytes: int = 131072) -> Dict[str, float]:
    """
    Task 2 & 3: Repeated patterns and NIST SP 800-22 Runs Test.
    Evaluates bit runs (transitions between 0 and 1, plus longest run of 0s and 1s)
    on a 1,048,576-bit (128 KB) prefix for fast execution, and evaluates
    adjacent 2-byte & 4-byte repeated blocks across the entire 1 MB stream.
    """
    sample = data[:bit_sample_bytes]
    # Convert sample bytes into a flat binary string of 1,048,576 bits
    bit_str = "".join(f"{b:08b}" for b in sample)
    n_bits = len(bit_str)

    ones = bit_str.count("1")
    pi = ones / n_bits

    # Count total runs V_n (1 + number of bit transitions) and longest runs
    runs = 1
    longest_one_run = 0
    longest_zero_run = 0
    current_run = 1

    for i in range(1, n_bits):
        if bit_str[i] != bit_str[i - 1]:
            runs += 1
            if bit_str[i - 1] == "1":
                if current_run > longest_one_run:
                    longest_one_run = current_run
            else:
                if current_run > longest_zero_run:
                    longest_zero_run = current_run
            current_run = 1
        else:
            current_run += 1

    # Check final run
    if bit_str[-1] == "1":
        longest_one_run = max(longest_one_run, current_run)
    else:
        longest_zero_run = max(longest_zero_run, current_run)

    # NIST Runs Test statistic and p-value
    expected_runs = 2.0 * n_bits * pi * (1.0 - pi) + 1.0
    denom = 2.0 * math.sqrt(2.0 * n_bits) * pi * (1.0 - pi)
    runs_z = abs(runs - expected_runs) / denom if denom > 0 else 0.0
    runs_p_value = math.erfc(runs_z / math.sqrt(2.0))

    # Byte-level repeated patterns across full 1 MB:
    # 1) Immediate adjacent byte repeats (X[i] == X[i+1], expected ~ N / 256)
    adj_byte_repeats = sum(1 for i in range(len(data) - 1) if data[i] == data[i + 1])
    expected_adj_repeats = (len(data) - 1) / 256.0

    # 2) Distinct 16-bit (2-byte) non-overlapping words out of 65,536 possible
    num_digrams = len(data) // 2
    digrams = [data[2 * i : 2 * i + 2] for i in range(num_digrams)]
    distinct_digrams = len(set(digrams))

    return {
        "bits_analyzed_for_runs": n_bits,
        "observed_runs": runs,
        "expected_runs": expected_runs,
        "runs_p_value": runs_p_value,
        "runs_pass": runs_p_value >= 0.01,
        "longest_one_run": longest_one_run,
        "longest_zero_run": longest_zero_run,
        "adjacent_byte_repeats": adj_byte_repeats,
        "expected_adjacent_repeats": expected_adj_repeats,
        "distinct_16bit_patterns": distinct_digrams,
    }


def analyze_serial_correlations(
    data: bytes, lags: List[int] = [1, 2, 8, 16]
) -> Dict[str, object]:
    """
    Task 2 & 3: Serial correlation coefficient r_k at lags k = 1, 2, 8, 16.
    For an independent uniform byte sequence, E[r_k] = 0 and 95% CI is +-1.96/sqrt(N).
    """
    n = len(data)
    mean_x = sum(data) / n
    var_sum = sum((b - mean_x) ** 2 for b in data)

    # Use memoryview for fast integer indexing over 1 MB
    mv = memoryview(data)
    lag_results: Dict[int, float] = {}

    for k in lags:
        cov_sum = sum((mv[i] - mean_x) * (mv[i + k] - mean_x) for i in range(n - k))
        r_k = cov_sum / var_sum if var_sum > 0 else 0.0
        lag_results[k] = r_k

    ci_95 = 1.96 / math.sqrt(n)
    all_within_bounds = all(abs(r) <= ci_95 * 1.5 for r in lag_results.values())

    return {
        "lags": lag_results,
        "confidence_bound_95": ci_95,
        "serial_correlation_pass": all_within_bounds,
    }


def evaluate_random_stream(name: str, data: bytes, method_desc: str = "") -> Dict[str, object]:
    """
    Runs the complete Task 2 & Task 3 statistical test suite on a byte stream.
    """
    byte_stats = analyze_byte_distribution(data)
    bit_stats = analyze_bit_distribution(data)
    pattern_stats = analyze_patterns_and_runs(data)
    corr_stats = analyze_serial_correlations(data)

    overall_pass = (
        byte_stats["chi2_pass"]
        and bit_stats["monobit_pass"]
        and pattern_stats["runs_pass"]
        and corr_stats["serial_correlation_pass"]
    )

    return {
        "name": name,
        "method": method_desc,
        "byte_stats": byte_stats,
        "bit_stats": bit_stats,
        "pattern_stats": pattern_stats,
        "corr_stats": corr_stats,
        "overall_pass": overall_pass,
    }
