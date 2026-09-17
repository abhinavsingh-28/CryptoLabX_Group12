# Assignment 6: Cryptanalysis of Vigenère Cipher using Kasiski Examination and Frequency Analysis

**Group 12 (Even Group – Ciphertext-2)**

## Overview

This program performs a complete cryptanalysis of a Vigenère cipher by combining the **Kasiski Examination** for key length estimation with **Frequency Analysis** (chi-squared statistic) for key recovery. The result is verified by re-encrypting the recovered plaintext and confirming it matches the original ciphertext.

## How to Run

```bash
cd attacks/vigenere_cryptanalysis/src
python3 main.py
```

The output is displayed in the terminal and saved to `outputs/analysis_output.txt`.

## Methodology

### Step 1: Preprocessing
- Remove all spaces, punctuation, and special characters from the ciphertext
- Normalize to uppercase A–Z characters only

### Step 2: Kasiski Examination (Key Length Estimation)
- Search for repeated trigrams and longer patterns in the ciphertext
- Calculate distances between repeated occurrences
- Factorize all distances; the most frequently occurring factor is the likely key length

### Step 3: Index of Coincidence Validation
- For each candidate key length, split the ciphertext into groups
- Calculate the average IC per group
- Key lengths producing an average IC close to English (≈ 0.0667) are most likely correct

### Step 4: Frequency Analysis
- Divide the ciphertext into columns by the estimated key length
- Each column is effectively a Caesar cipher with one key letter
- Use the chi-squared statistic to determine the shift for each column

### Step 5: Key Recovery & Decryption
- Combine individual shifts to form the Vigenère key
- Decrypt: `P = (C - K) mod 26`

### Step 6: Verification
- Re-encrypt the plaintext: `C = (P + K) mod 26`
- Compare with the original ciphertext to confirm correctness

## Results

| Item | Value |
|---|---|
| **Estimated Key Length** | 12 |
| **Recovered Key** | `UNITEDSTATES` |
| **Verification** | ✅ PASSED |

## User-Defined Functions

| Function | File | Purpose |
|---|---|---|
| `clean_ciphertext()` | `kasiski.py` | Remove spaces/special characters and normalize the ciphertext |
| `find_repeated_patterns()` | `kasiski.py` | Identify repeated sequences in the ciphertext |
| `calculate_distances()` | `kasiski.py` | Find distances between repeated occurrences |
| `find_factors()` | `kasiski.py` | Find factors of the distances obtained from repeated patterns |
| `kasiski_analysis()` | `kasiski.py` | Use repeated patterns/distances to suggest candidate key lengths |
| `calculate_ic()` | `frequency.py` | Calculate Index of Coincidence |
| `split_into_groups()` | `frequency.py` | Divide ciphertext according to a candidate key length |
| `frequency_analysis()` | `frequency.py` | Calculate A–Z frequency for each group |
| `find_shift()` | `frequency.py` | Estimate the Caesar shift for a group |
| `find_key()` | `vigenere.py` | Combine shifts to obtain the probable Vigenère key |
| `vigenere_decrypt()` | `vigenere.py` | Decrypt ciphertext using the recovered key |
| `vigenere_encrypt()` | `vigenere.py` | Re-encrypt plaintext for verification |
| `verify()` | `vigenere.py` | Check whether re-encryption produces the original ciphertext |

## Project Structure

```
attacks/vigenere_cryptanalysis/
├── data/
│   └── ciphertext.txt          # Ciphertext-2 (Even Group Numbers)
├── outputs/
│   └── analysis_output.txt     # Generated analysis results
├── src/
│   ├── __init__.py
│   ├── kasiski.py              # Kasiski examination functions
│   ├── frequency.py            # Frequency analysis functions
│   ├── vigenere.py             # Encryption, decryption, verification
│   └── main.py                 # Main driver program
└── README.md                   # This file
```
