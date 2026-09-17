"""
Frequency Analysis Module
-------------------------
Implements frequency analysis techniques for breaking each Caesar-shifted
column of a Vigenere cipher.
Functions: calculate_ic, split_into_groups, frequency_analysis, find_shift
"""

import string


# Standard English letter frequencies (A-Z)
ENGLISH_FREQUENCIES = {
    'A': 0.08167, 'B': 0.01492, 'C': 0.02782, 'D': 0.04253, 'E': 0.12702,
    'F': 0.02228, 'G': 0.02015, 'H': 0.06094, 'I': 0.06966, 'J': 0.00153,
    'K': 0.00772, 'L': 0.04025, 'M': 0.02406, 'N': 0.06749, 'O': 0.07507,
    'P': 0.01929, 'Q': 0.00095, 'R': 0.05987, 'S': 0.06327, 'T': 0.09056,
    'U': 0.02758, 'V': 0.00978, 'W': 0.02360, 'X': 0.00150, 'Y': 0.01974,
    'Z': 0.00074
}

# Expected IC for English text (monographic)
ENGLISH_IC = 0.0667


def calculate_ic(text):
    """
    Calculate the Index of Coincidence for a given text.
    
    IC measures how likely it is that two randomly chosen letters from
    the text are the same. English text has IC ≈ 0.0667, while random
    text has IC ≈ 0.0385.
    
    Formula: IC = Σ(fi * (fi - 1)) / (N * (N - 1))
    where fi = frequency of each letter, N = total letters
    
    Args:
        text (str): Text to calculate IC for (should be uppercase A-Z only).
        
    Returns:
        float: The Index of Coincidence value.
    """
    n = len(text)
    if n <= 1:
        return 0.0
    
    freq = {}
    for char in string.ascii_uppercase:
        freq[char] = 0
    
    for char in text:
        if char in freq:
            freq[char] += 1
    
    numerator = sum(f * (f - 1) for f in freq.values())
    denominator = n * (n - 1)
    
    return numerator / denominator if denominator > 0 else 0.0


def split_into_groups(ciphertext, key_length):
    """
    Divide the ciphertext into groups according to a candidate key length.
    
    Each group i contains every key_length-th character starting from
    position i. If the key length is correct, each group was encrypted
    with the same Caesar shift.
    
    Args:
        ciphertext (str): Cleaned ciphertext (uppercase, no spaces).
        key_length (int): The candidate key length to split by.
        
    Returns:
        list: A list of strings, where groups[i] contains characters
              at positions i, i+key_length, i+2*key_length, ...
    """
    groups = ['' for _ in range(key_length)]
    
    for i, char in enumerate(ciphertext):
        group_index = i % key_length
        groups[group_index] += char
    
    return groups


def frequency_analysis(group):
    """
    Calculate A-Z frequency counts and percentages for a group.
    
    Args:
        group (str): A string of uppercase letters (one column group).
        
    Returns:
        dict: Dictionary with keys:
              - 'counts': dict mapping each letter A-Z to its count
              - 'percentages': dict mapping each letter A-Z to its percentage
              - 'total': total number of characters in the group
    """
    total = len(group)
    counts = {}
    percentages = {}
    
    for char in string.ascii_uppercase:
        counts[char] = 0
    
    for char in group:
        if char in counts:
            counts[char] += 1
    
    for char in string.ascii_uppercase:
        percentages[char] = (counts[char] / total * 100) if total > 0 else 0.0
    
    return {
        'counts': counts,
        'percentages': percentages,
        'total': total
    }


def find_shift(group):
    """
    Estimate the Caesar shift for a single group using chi-squared
    statistic against standard English letter frequencies.
    
    For each possible shift (0-25), "decrypt" the group by that shift
    and measure how closely the resulting letter frequencies match
    expected English frequencies using the chi-squared statistic.
    The shift with the lowest chi-squared value is the best estimate.
    
    Args:
        group (str): A string of uppercase letters (one column group).
        
    Returns:
        tuple: (best_shift, chi_squared_scores)
            - best_shift: int, the estimated shift value (0-25)
            - chi_squared_scores: list of (shift, chi_sq) for all 26 shifts
    """
    n = len(group)
    if n == 0:
        return 0, []
    
    # Count frequency of each letter in the group
    freq = {}
    for char in string.ascii_uppercase:
        freq[char] = 0
    for char in group:
        if char in freq:
            freq[char] += 1
    
    best_shift = 0
    min_chi_sq = float('inf')
    chi_squared_scores = []
    
    for shift in range(26):
        chi_sq = 0.0
        for i in range(26):
            # Letter in ciphertext
            cipher_letter = string.ascii_uppercase[i]
            # What this letter would map to if we decrypt with this shift
            plain_letter = string.ascii_uppercase[(i - shift) % 26]
            
            observed = freq[cipher_letter]
            expected = n * ENGLISH_FREQUENCIES[plain_letter]
            
            if expected > 0:
                chi_sq += ((observed - expected) ** 2) / expected
        
        chi_squared_scores.append((shift, chi_sq))
        
        if chi_sq < min_chi_sq:
            min_chi_sq = chi_sq
            best_shift = shift
    
    return best_shift, chi_squared_scores
