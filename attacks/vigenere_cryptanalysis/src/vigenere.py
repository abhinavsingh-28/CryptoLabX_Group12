"""
Vigenere Cipher Module
----------------------
Implements Vigenere encryption, decryption, key recovery, and verification.
Functions: find_key, vigenere_decrypt, vigenere_encrypt, verify
"""

import string
from frequency import split_into_groups, find_shift


def find_key(ciphertext, key_length):
    """
    Combine shifts from each group to obtain the probable Vigenere key.
    
    Splits the ciphertext into groups by key_length, estimates the
    Caesar shift for each group, and converts shifts to key letters.
    
    Args:
        ciphertext (str): Cleaned ciphertext (uppercase, no spaces).
        key_length (int): The estimated key length.
        
    Returns:
        tuple: (key, shifts, shift_details)
            - key: str, the recovered key as uppercase letters
            - shifts: list of int, the shift value for each position
            - shift_details: list of (shift, chi_sq_scores) per group
    """
    groups = split_into_groups(ciphertext, key_length)
    
    shifts = []
    shift_details = []
    key_letters = []
    
    for group in groups:
        best_shift, chi_sq_scores = find_shift(group)
        shifts.append(best_shift)
        shift_details.append((best_shift, chi_sq_scores))
        # Convert shift number to letter (0=A, 1=B, ..., 25=Z)
        key_letters.append(string.ascii_uppercase[best_shift])
    
    key = ''.join(key_letters)
    return key, shifts, shift_details


def vigenere_decrypt(ciphertext, key):
    """
    Decrypt ciphertext using the recovered Vigenere key.
    
    Each ciphertext letter is shifted back by the corresponding
    key letter: P = (C - K) mod 26
    
    Args:
        ciphertext (str): Cleaned ciphertext (uppercase, no spaces).
        key (str): The Vigenere key (uppercase letters).
        
    Returns:
        str: The decrypted plaintext (uppercase).
    """
    plaintext = []
    key_length = len(key)
    key_index = 0
    
    for char in ciphertext:
        if char.upper() in string.ascii_uppercase:
            # Get shift value from key letter
            shift = ord(key[key_index % key_length]) - ord('A')
            # Decrypt: P = (C - K) mod 26
            decrypted = chr((ord(char.upper()) - ord('A') - shift) % 26 + ord('A'))
            plaintext.append(decrypted)
            key_index += 1
        else:
            plaintext.append(char)
    
    return ''.join(plaintext)


def vigenere_encrypt(plaintext, key):
    """
    Re-encrypt plaintext for verification purposes.
    
    Each plaintext letter is shifted forward by the corresponding
    key letter: C = (P + K) mod 26
    
    Args:
        plaintext (str): The plaintext to encrypt (uppercase).
        key (str): The Vigenere key (uppercase letters).
        
    Returns:
        str: The encrypted ciphertext (uppercase).
    """
    ciphertext = []
    key_length = len(key)
    key_index = 0
    
    for char in plaintext:
        if char.upper() in string.ascii_uppercase:
            # Get shift value from key letter
            shift = ord(key[key_index % key_length]) - ord('A')
            # Encrypt: C = (P + K) mod 26
            encrypted = chr((ord(char.upper()) - ord('A') + shift) % 26 + ord('A'))
            ciphertext.append(encrypted)
            key_index += 1
        else:
            ciphertext.append(char)
    
    return ''.join(ciphertext)


def verify(original_ciphertext, recovered_plaintext, key):
    """
    Check whether re-encryption of the recovered plaintext produces
    the original ciphertext.
    
    Args:
        original_ciphertext (str): The original cleaned ciphertext.
        recovered_plaintext (str): The decrypted plaintext.
        key (str): The Vigenere key used.
        
    Returns:
        tuple: (is_match, re_encrypted)
            - is_match: bool, True if re-encryption matches original
            - re_encrypted: str, the re-encrypted text
    """
    re_encrypted = vigenere_encrypt(recovered_plaintext, key)
    is_match = (re_encrypted == original_ciphertext)
    return is_match, re_encrypted
