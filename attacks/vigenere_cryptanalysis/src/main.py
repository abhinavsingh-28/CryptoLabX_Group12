"""
Vigenere Cipher Cryptanalysis - Main Driver
============================================
Assignment 6 - Group 12 (Even Group - Ciphertext-2)

Performs complete cryptanalysis of a Vigenere cipher using:
  1. Kasiski Examination for key length estimation
  2. Index of Coincidence for key length validation
  3. Frequency Analysis (chi-squared) for key recovery
  4. Decryption and verification by re-encryption
"""

import os
import sys
import string

# Add current directory to path for local imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from kasiski import clean_ciphertext, find_repeated_patterns, calculate_distances, find_factors, kasiski_analysis
from frequency import calculate_ic, split_into_groups, frequency_analysis, find_shift, ENGLISH_IC
from vigenere import find_key, vigenere_decrypt, vigenere_encrypt, verify


# ─────────────────────────── Display Helpers ────────────────────────────

def print_header(title):
    """Print a formatted section header."""
    width = 80
    print("\n" + "=" * width)
    print(f"  {title}")
    print("=" * width)


def print_subheader(title):
    """Print a formatted subsection header."""
    print(f"\n--- {title} ---")


def display_kasiski_results(candidates, pattern_details):
    """Display Kasiski examination results."""
    print_header("STEP 1: KASISKI EXAMINATION")

    # Show top repeated patterns
    print_subheader("Top Repeated Patterns Found")
    print(f"{'Pattern':<12} {'Positions':<30} {'Distances':<25} {'Factors'}")
    print("-" * 90)

    # Sort by pattern length (longer = more significant), then alphabetically
    sorted_patterns = sorted(
        pattern_details.items(),
        key=lambda x: (-len(x[0]), x[0])
    )

    count = 0
    for pattern, info in sorted_patterns:
        if count >= 15:  # Show top 15 patterns
            break
        positions_str = str(info['positions'][:5])
        if len(info['positions']) > 5:
            positions_str = positions_str[:-1] + ", ...]"
        distances_str = str(info['distances'][:5])
        if len(info['distances']) > 5:
            distances_str = distances_str[:-1] + ", ...]"
        # Get unique factors for these distances
        unique_factors = sorted(set(info['factors']))[:8]
        factors_str = str(unique_factors)
        print(f"{pattern:<12} {positions_str:<30} {distances_str:<25} {factors_str}")
        count += 1

    # Show factor frequency ranking
    print_subheader("Factor Frequency Ranking (Top Candidates for Key Length)")
    print(f"{'Factor':<10} {'Frequency':<12} {'Likelihood'}")
    print("-" * 45)

    for factor, freq in candidates[:10]:
        if factor <= 20:  # Only show reasonable key lengths
            bar = "█" * min(freq, 40)
            print(f"{factor:<10} {freq:<12} {bar}")


def display_ic_results(ciphertext, candidates):
    """Display IC analysis for candidate key lengths."""
    print_header("STEP 2: INDEX OF COINCIDENCE VALIDATION")
    print(f"\nExpected English IC: {ENGLISH_IC:.4f}")
    print(f"Expected Random IC:  0.0385\n")
    print(f"{'Key Length':<12} {'Average IC':<12} {'Assessment'}")
    print("-" * 50)

    for factor, _ in candidates[:10]:
        if 2 <= factor <= 20:
            groups = split_into_groups(ciphertext, factor)
            avg_ic = sum(calculate_ic(g) for g in groups) / len(groups)
            
            if avg_ic >= 0.060:
                assessment = "★★★ Strong match"
            elif avg_ic >= 0.050:
                assessment = "★★  Possible match"
            else:
                assessment = "★   Unlikely"
            
            print(f"{factor:<12} {avg_ic:<12.4f} {assessment}")


def display_frequency_tables(groups, key_length):
    """Display frequency analysis tables for each group."""
    print_header("STEP 3: FREQUENCY ANALYSIS")

    for i, group in enumerate(groups):
        freq_data = frequency_analysis(group)
        shift, _ = find_shift(group)
        key_letter = string.ascii_uppercase[shift]

        print(f"\n  Group {i + 1} (Key position {i + 1}, "
              f"Estimated shift: {shift} = '{key_letter}', "
              f"Group size: {freq_data['total']} chars)")
        print("  " + "-" * 70)
        
        # Print frequency table in 2 rows of 13 letters each
        for row_start in range(0, 26, 13):
            row_end = min(row_start + 13, 26)
            letters = string.ascii_uppercase[row_start:row_end]
            
            # Letter header
            header = "  "
            for letter in letters:
                header += f"{letter:>5}"
            print(header)
            
            # Count row
            count_row = "  "
            for letter in letters:
                count_row += f"{freq_data['counts'][letter]:>5}"
            print(count_row)
            
            # Percentage row
            pct_row = "  "
            for letter in letters:
                pct_row += f"{freq_data['percentages'][letter]:>4.1f}%"
            print(pct_row)
            print()


def display_results(key, plaintext, is_match, ciphertext, re_encrypted):
    """Display final results: key, plaintext, and verification."""
    print_header("STEP 4: KEY RECOVERY")
    print(f"\n  Recovered Key: {key}")
    print(f"  Key Length:    {len(key)}")
    print(f"  Key Letters:   {' - '.join(key)}")
    print(f"  Key Shifts:    {' - '.join(str(ord(c) - ord('A')) for c in key)}")

    print_header("STEP 5: DECRYPTED PLAINTEXT")
    # Display plaintext in blocks of 5, 10 groups per line
    for i in range(0, len(plaintext), 50):
        chunk = plaintext[i:i+50]
        formatted = ' '.join(chunk[j:j+5] for j in range(0, len(chunk), 5))
        print(f"  {formatted}")

    print_header("STEP 6: VERIFICATION (Re-encryption)")
    print(f"\n  Re-encryption matches original: {'YES ✓' if is_match else 'NO ✗'}")
    
    if is_match:
        print("  Verification PASSED - The recovered key correctly decrypts the ciphertext.")
    else:
        print("  Verification FAILED - There may be errors in the recovered key.")
        # Show where differences occur
        diff_count = 0
        for i, (orig, reenc) in enumerate(zip(ciphertext, re_encrypted)):
            if orig != reenc:
                diff_count += 1
                if diff_count <= 10:
                    print(f"    Position {i}: original='{orig}' re-encrypted='{reenc}'")
        if diff_count > 10:
            print(f"    ... and {diff_count - 10} more differences")
        print(f"  Total mismatches: {diff_count} out of {len(ciphertext)}")


# ─────────────────────────── Main Program ───────────────────────────────

def main():
    """Main cryptanalysis driver."""

    # ──────── Load Ciphertext ────────
    data_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        '..', 'data', 'ciphertext.txt'
    )
    
    with open(data_path, 'r') as f:
        raw_ciphertext = f.read()

    print_header("VIGENÈRE CIPHER CRYPTANALYSIS")
    print("  Assignment 6 - Group 12 (Even Group - Ciphertext-2)")
    print("  Method: Kasiski Examination + Frequency Analysis")

    # ──────── Step 1: Preprocess ────────
    ciphertext = clean_ciphertext(raw_ciphertext)
    print(f"\n  Ciphertext length: {len(ciphertext)} characters")
    print(f"  First 80 chars:   {ciphertext[:80]}...")

    # ──────── Step 2: Kasiski Examination ────────
    candidates, factor_counts, pattern_details = kasiski_analysis(ciphertext)
    display_kasiski_results(candidates, pattern_details)

    # ──────── Step 3: IC Validation ────────
    display_ic_results(ciphertext, candidates)

    # Determine the best key length using IC
    best_key_length = None
    best_ic = 0
    for factor, _ in candidates[:15]:
        if 2 <= factor <= 20:
            groups = split_into_groups(ciphertext, factor)
            avg_ic = sum(calculate_ic(g) for g in groups) / len(groups)
            if avg_ic > best_ic:
                best_ic = avg_ic
                best_key_length = factor

    if best_key_length is None:
        # Fallback: use the most frequent factor
        for factor, _ in candidates:
            if 2 <= factor <= 20:
                best_key_length = factor
                break

    print(f"\n  >>> Selected Key Length: {best_key_length} (Average IC: {best_ic:.4f})")

    # ──────── Step 4: Frequency Analysis ────────
    groups = split_into_groups(ciphertext, best_key_length)
    display_frequency_tables(groups, best_key_length)

    # ──────── Step 5: Key Recovery ────────
    key, shifts, shift_details = find_key(ciphertext, best_key_length)

    # ──────── Step 6: Decrypt ────────
    plaintext = vigenere_decrypt(ciphertext, key)

    # ──────── Step 7: Verify ────────
    is_match, re_encrypted = verify(ciphertext, plaintext, key)

    # ──────── Display Results ────────
    display_results(key, plaintext, is_match, ciphertext, re_encrypted)

    # ──────── Save Output ────────
    output_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        '..', 'outputs', 'analysis_output.txt'
    )
    
    # Redirect stdout to capture output to file as well
    import io
    from contextlib import redirect_stdout

    buffer = io.StringIO()
    with redirect_stdout(buffer):
        print(f"Vigenere Cipher Cryptanalysis - Group 12")
        print(f"Estimated Key Length: {best_key_length}")
        print(f"Recovered Key: {key}")
        print(f"Key Shifts: {shifts}")
        print(f"\nRecovered Plaintext:")
        print(plaintext)
        print(f"\nVerification: {'PASSED' if is_match else 'FAILED'}")

    with open(output_path, 'w') as f:
        f.write(buffer.getvalue())
    
    print(f"\n  Output saved to: {output_path}")
    print("\n" + "=" * 80)
    print("  CRYPTANALYSIS COMPLETE")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()
