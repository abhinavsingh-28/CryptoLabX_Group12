"""
Kasiski Examination Module
--------------------------
Implements the Kasiski test to estimate the key length of a Vigenere cipher.
Functions: clean_ciphertext, find_repeated_patterns, calculate_distances,
           find_factors, kasiski_analysis
"""

import re
from collections import defaultdict


def clean_ciphertext(ciphertext):
    """
    Remove spaces/special characters and normalize the ciphertext.
    Converts to uppercase and keeps only alphabetic characters.
    
    Args:
        ciphertext (str): Raw ciphertext with spaces and formatting.
        
    Returns:
        str: Cleaned uppercase ciphertext with only A-Z characters.
    """
    # Remove all non-alphabetic characters and convert to uppercase
    cleaned = re.sub(r'[^A-Za-z]', '', ciphertext)
    return cleaned.upper()


def find_repeated_patterns(ciphertext, min_length=3, max_length=6):
    """
    Identify repeated sequences (trigrams and longer) in the ciphertext.
    
    Args:
        ciphertext (str): Cleaned ciphertext (uppercase, no spaces).
        min_length (int): Minimum pattern length to search for (default: 3).
        max_length (int): Maximum pattern length to search for (default: 6).
        
    Returns:
        dict: Dictionary mapping each repeated pattern to a list of
              starting positions (0-indexed) where it occurs.
    """
    patterns = defaultdict(list)
    text_len = len(ciphertext)
    
    for length in range(min_length, max_length + 1):
        for i in range(text_len - length + 1):
            pattern = ciphertext[i:i + length]
            patterns[pattern].append(i)
    
    # Keep only patterns that appear more than once
    repeated = {
        pattern: positions
        for pattern, positions in patterns.items()
        if len(positions) > 1
    }
    
    return repeated


def calculate_distances(repeated_patterns):
    """
    Find distances between repeated occurrences of each pattern.
    
    Args:
        repeated_patterns (dict): Dictionary mapping patterns to their
                                  list of starting positions.
        
    Returns:
        dict: Dictionary mapping each pattern to a list of distances
              between consecutive occurrences.
    """
    distances = {}
    
    for pattern, positions in repeated_patterns.items():
        pattern_distances = []
        for i in range(len(positions)):
            for j in range(i + 1, len(positions)):
                distance = positions[j] - positions[i]
                pattern_distances.append(distance)
        if pattern_distances:
            distances[pattern] = pattern_distances
    
    return distances


def find_factors(number):
    """
    Find all factors of a given number (useful for determining
    candidate key lengths from distances).
    
    Args:
        number (int): The number to factorize.
        
    Returns:
        list: Sorted list of all factors of the number (excluding 1).
    """
    factors = []
    for i in range(2, number + 1):
        if number % i == 0:
            factors.append(i)
    return sorted(factors)


def kasiski_analysis(ciphertext, min_pattern_len=3, max_pattern_len=5):
    """
    Use repeated patterns and their distances to suggest candidate key lengths.
    Performs the full Kasiski examination pipeline.
    
    Steps:
        1. Find repeated patterns in the ciphertext.
        2. Calculate distances between repeated occurrences.
        3. Find factors of all distances.
        4. Count factor frequencies - the most common factors are
           likely key length candidates.
    
    Args:
        ciphertext (str): Cleaned ciphertext (uppercase, no spaces).
        min_pattern_len (int): Minimum pattern length to search for.
        max_pattern_len (int): Maximum pattern length to search for.
        
    Returns:
        tuple: (candidate_key_lengths, factor_counts, pattern_details)
            - candidate_key_lengths: list of (factor, count) sorted by frequency
            - factor_counts: dict of factor -> count
            - pattern_details: dict with pattern info for display
    """
    # Step 1: Find repeated patterns
    repeated = find_repeated_patterns(ciphertext, min_pattern_len, max_pattern_len)
    
    # Step 2: Calculate distances
    distances = calculate_distances(repeated)
    
    # Step 3 & 4: Find factors and count their frequencies
    factor_counts = defaultdict(int)
    pattern_details = {}
    
    for pattern, dists in distances.items():
        all_factors = []
        for d in dists:
            factors = find_factors(d)
            all_factors.extend(factors)
            for f in factors:
                factor_counts[f] += 1
        pattern_details[pattern] = {
            'positions': repeated[pattern],
            'distances': dists,
            'factors': all_factors
        }
    
    # Sort candidates by frequency (most common factor = most likely key length)
    candidate_key_lengths = sorted(
        factor_counts.items(),
        key=lambda x: x[1],
        reverse=True
    )
    
    return candidate_key_lengths, dict(factor_counts), pattern_details
