import os
from shift_cipher import decrypt

def load_dictionary():
    dict_path = os.path.join(os.path.dirname(__file__), '../dictionary/english_words.txt')
    with open(dict_path, 'r') as f:
        return set(word.strip().lower() for word in f)

def dictionary_attack(ciphertext):
    english_words = load_dictionary()
    best_key, max_score = 0, 0
    
    for key in range(26):
        plaintext = decrypt(ciphertext, key)
        words = plaintext.lower().split()
        score = sum(1 for word in words if word in english_words)
        
        if score > max_score:
            max_score = score
            best_key = key
            
    return best_key
