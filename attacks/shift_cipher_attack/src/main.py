from shift_cipher import encrypt
from brute_force_dictionary import dictionary_attack
from chi_square_attack import chi_square_attack

def main():
    test_cases = [
        ("The quick brown fox jumps over the lazy dog", 7),
        ("Hello world this is a test of the shift cipher", 14)
    ]
    
    print(f"{'Test Case':<15} | {'Actual Key':<10} | {'Dict Key':<8} | {'Chi-Sq Key':<10} | {'Dict Correct?':<13} | {'Chi-Sq Correct?'}")
    print("-" * 85)
    
    for i, (text, actual_key) in enumerate(test_cases):
        ciphertext = encrypt(text, actual_key)
        
        dict_key = dictionary_attack(ciphertext)
        chi_key = chi_square_attack(ciphertext)
        
        dict_correct = dict_key == actual_key
        chi_correct = chi_key == actual_key
        
        print(f"Test {i+1:<10} | {actual_key:<10} | {dict_key:<8} | {chi_key:<10} | {str(dict_correct):<13} | {str(chi_correct)}")

if __name__ == "__main__":
    main()
