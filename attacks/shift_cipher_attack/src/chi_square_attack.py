from shift_cipher import decrypt

# Standard English letter frequencies
ENGLISH_FREQS = {
    'a': 0.082, 'b': 0.015, 'c': 0.028, 'd': 0.043, 'e': 0.130, 'f': 0.022,
    'g': 0.020, 'h': 0.061, 'i': 0.070, 'j': 0.002, 'k': 0.008, 'l': 0.040,
    'm': 0.024, 'n': 0.067, 'o': 0.075, 'p': 0.019, 'q': 0.001, 'r': 0.060,
    's': 0.063, 't': 0.091, 'u': 0.028, 'v': 0.010, 'w': 0.023, 'x': 0.001,
    'y': 0.020, 'z': 0.001
}

def chi_square_attack(ciphertext):
    best_key = 0
    min_chi_square = float('inf')
    text_length = sum(1 for c in ciphertext if c.isalpha())
    
    if text_length == 0: return 0

    for key in range(26):
        plaintext = decrypt(ciphertext, key).lower()
        chi_square = 0
        
        for char in "abcdefghijklmnopqrstuvwxyz":
            observed = plaintext.count(char)
            expected = text_length * ENGLISH_FREQS[char]
            if expected > 0:
                chi_square += ((observed - expected) ** 2) / expected
                
        if chi_square < min_chi_square:
            min_chi_square = chi_square
            best_key = key
            
    return best_key
