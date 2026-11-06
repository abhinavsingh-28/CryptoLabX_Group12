"""
Assignment 9: Complete Lab Demonstration Runner (Tasks 1, 2 & 3)
Generates 1 MB from Linux /dev/urandom, OpenSSL rand, and Windows CNG,
evaluates statistical distributions and hypothesis tests, and saves the
report to outputs/assignment9_output.txt.
"""

import io
import os
import sys

# Guard against local 'math/' directory shadowing Python's stdlib 'math'
_PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
_SHADOWED = [p for p in sys.path if os.path.abspath(p or ".") == _PROJECT_ROOT]
for _p in _SHADOWED:
    sys.path.remove(_p)

import math  # noqa: F401
from contextlib import redirect_stdout
from typing import Dict

sys.path.extend(_SHADOWED)

from modern.os_csprng_generator import ONE_MB, generate_all_samples
from analysis.rng_statistical_analysis import evaluate_random_stream


def print_detailed_report(reports: Dict[str, Dict[str, object]]) -> None:
    print("*" * 80)
    print("CRYPTOGRAPHY LAB - ASSIGNMENT 9 DEMONSTRATION")
    print("Evaluation of OS & Cryptographic Random-Number Generation Mechanisms")
    print("*" * 80)

    for key, rep in reports.items():
        b_st = rep["byte_stats"]
        bit_st = rep["bit_stats"]
        pat_st = rep["pattern_stats"]
        cor_st = rep["corr_stats"]
        lags = cor_st["lags"]

        print("\n" + "=" * 80)
        print(f"SOURCE: {key.upper()} -> {rep['method']}")
        print("=" * 80)

        print("  [1] Byte-Frequency Distribution & Chi-Square Test (1,048,576 bytes):")
        print(f"      Expected Count / Byte : {b_st['expected_per_byte']:.1f}")
        print(f"      Min / Max Byte Count  : {b_st['min_byte_count']} / {b_st['max_byte_count']}")
        print(f"      Std Dev of Counts     : {b_st['std_dev_byte_count']:.2f}")
        print(f"      Shannon Entropy       : {b_st['shannon_entropy']:.6f} bits/byte (Ideal = 8.000000)")
        print(f"      Chi-Square (df=255)   : {b_st['chi2_statistic']:.4f} (p-value = {b_st['chi2_p_value']:.4f}) -> {'PASS' if b_st['chi2_pass'] else 'FAIL'}")

        print("\n  [2] Bit Distribution & NIST Frequency (Monobit) Test (8,388,608 bits):")
        print(f"      Ones / Zeros Count    : {bit_st['ones_count']:,} / {bit_st['zeros_count']:,}")
        print(f"      Proportion of Ones    : {bit_st['ones_proportion']:.6f} (Ideal = 0.500000)")
        print(f"      Monobit S_obs         : {bit_st['monobit_s_obs']:.4f} (p-value = {bit_st['monobit_p_value']:.4f}) -> {'PASS' if bit_st['monobit_pass'] else 'FAIL'}")

        print("\n  [3] Repeated Patterns & NIST Runs Test:")
        print(f"      Observed / Exp. Runs  : {pat_st['observed_runs']:,} / {pat_st['expected_runs']:,.1f} (in {pat_st['bits_analyzed_for_runs']:,} bits)")
        print(f"      Runs Test p-value     : {pat_st['runs_p_value']:.4f} -> {'PASS' if pat_st['runs_pass'] else 'FAIL'}")
        print(f"      Longest 1-Run / 0-Run : {pat_st['longest_one_run']} bits / {pat_st['longest_zero_run']} bits")
        print(f"      Adjacent Byte Repeats : {pat_st['adjacent_byte_repeats']:,} (Expected = {pat_st['expected_adjacent_repeats']:,.1f})")
        print(f"      Distinct 16-bit Words : {pat_st['distinct_16bit_patterns']:,} / 65,536")

        print("\n  [4] Serial Autocorrelation (95% CI Bound = +/-" + f"{cor_st['confidence_bound_95']:.6f}):")
        print(
            f"      Lag-1: {lags[1]:+.6f} | Lag-2: {lags[2]:+.6f} | "
            f"Lag-8: {lags[8]:+.6f} | Lag-16: {lags[16]:+.6f} -> "
            f"{'PASS' if cor_st['serial_correlation_pass'] else 'FAIL'}"
        )

    print("\n" + "=" * 80)
    print("SUMMARY COMPARISON TABLE (ALPHA = 0.01 SIGNIFICANCE LEVEL)")
    print("=" * 80)
    header = f"{'Source':<16} | {'Entropy':<10} | {'Chi2 (p-val)':<16} | {'Monobit p':<10} | {'Runs p':<10} | {'Lag-1 Corr':<11} | {'Verdict'}"
    print(header)
    print("-" * len(header))
    for key, rep in reports.items():
        b_st = rep["byte_stats"]
        bit_st = rep["bit_stats"]
        pat_st = rep["pattern_stats"]
        cor_st = rep["corr_stats"]
        chi2_str = f"{b_st['chi2_statistic']:.1f} ({b_st['chi2_p_value']:.3f})"
        verdict = "PASS ALL" if rep["overall_pass"] else "CHECK"
        print(
            f"{key:<16} | {b_st['shannon_entropy']:<10.6f} | {chi2_str:<16} | "
            f"{bit_st['monobit_p_value']:<10.4f} | {pat_st['runs_p_value']:<10.4f} | "
            f"{cor_st['lags'][1]:<+11.6f} | {verdict}"
        )
    print("=" * 80)


def main() -> None:
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        samples = generate_all_samples(ONE_MB)
        reports = {}
        for key, info in samples.items():
            reports[key] = evaluate_random_stream(
                name=key,
                data=info["data"],
                method_desc=str(info["method"]),
            )
        print_detailed_report(reports)

    output_text = buffer.getvalue()
    sys.stdout.write(output_text)

    os.makedirs("outputs", exist_ok=True)
    output_path = os.path.join("outputs", "assignment9_output.txt")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(output_text)

    print(f"\n[+] Saved complete Assignment 9 report to: {output_path}")


if __name__ == "__main__":
    main()