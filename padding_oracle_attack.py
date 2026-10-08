import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# ==========================================
# SIMULATED SERVER (Target)
# ==========================================
SECRET_KEY = os.urandom(16) # The attacker NEVER sees this
BLOCK_SIZE = 16

def encrypt(plaintext: bytes) -> tuple:
    """Encrypts plaintext using AES-CBC with PKCS#7 padding."""
    iv = os.urandom(BLOCK_SIZE)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(SECRET_KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv, ciphertext

def padding_oracle(iv: bytes, ciphertext: bytes) -> bool:
    """Returns True if the decrypted ciphertext has valid PKCS#7 padding, False otherwise."""
    cipher = Cipher(algorithms.AES(SECRET_KEY), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    try:
        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        unpadder.update(decrypted_padded) + unpadder.finalize()
        return True
    except ValueError:
        return False

# ==========================================
# ATTACKER CODE (Deliverable 2)
# ==========================================
oracle_queries = 0

def query_oracle(iv: bytes, ciphertext: bytes) -> bool:
    """Wrapper to count queries made to the oracle."""
    global oracle_queries
    oracle_queries += 1
    return padding_oracle(iv, ciphertext)

def attack_single_block(prev_block: bytes, target_block: bytes) -> bytes:
    """Recovers the plaintext of a single target block using the previous block."""
    intermediate_state = bytearray(BLOCK_SIZE)
    recovered_plaintext = bytearray(BLOCK_SIZE)

    # Recover bytes from right to left (index 15 down to 0)
    for padding_val in range(1, BLOCK_SIZE + 1):
        target_index = BLOCK_SIZE - padding_val
        modified_prev_block = bytearray(prev_block)

        # Prepare the modified previous block for bytes we've already solved
        for i in range(target_index + 1, BLOCK_SIZE):
            modified_prev_block[i] = intermediate_state[i] ^ padding_val

        # Guess the byte at target_index (0 to 255)
        match_found = False
        for guess in range(256):
            modified_prev_block[target_index] = guess
            
            # Send only the manipulated block and target block to the oracle
            if query_oracle(bytes(modified_prev_block), target_block):
                
                # Edge case: Ensure we didn't accidentally hit a valid but incorrect padding (e.g., \x02\x02)
                if padding_val == 1:
                    modified_prev_block[target_index - 1] ^= 1 # Flip a bit in the preceding byte
                    if not query_oracle(bytes(modified_prev_block), target_block):
                        modified_prev_block[target_index - 1] ^= 1 # Revert if false positive
                        continue
                        
                # Correct guess found
                intermediate_byte = guess ^ padding_val
                intermediate_state[target_index] = intermediate_byte
                recovered_plaintext[target_index] = intermediate_byte ^ prev_block[target_index]
                match_found = True
                break
                
        if not match_found:
            raise Exception("Failed to find valid padding. Check oracle connection.")
            
    return bytes(recovered_plaintext)

def padding_oracle_attack(iv: bytes, ciphertext: bytes) -> bytes:
    """Orchestrates the attack across all ciphertext blocks."""
    blocks = [iv] + [ciphertext[i:i+BLOCK_SIZE] for i in range(0, len(ciphertext), BLOCK_SIZE)]
    recovered_message = b""
    
    for i in range(1, len(blocks)):
        print(f"[*] Attacking block {i}/{len(blocks)-1}...")
        recovered_block = attack_single_block(blocks[i-1], blocks[i])
        recovered_message += recovered_block
        
    # Strip PKCS#7 padding from the final recovered plaintext
    padding_len = recovered_message[-1]
    return recovered_message[:-padding_len]

if __name__ == "__main__":
    print("--- Setting up Scenario ---")
    secret_message = b"This is a classified message demonstrating the padding oracle attack."
    iv, ciphertext = encrypt(secret_message)
    
    print(f"Original Ciphertext length: {len(ciphertext)} bytes")
    print("\n[*] Starting Padding Oracle Attack (Zero knowledge of AES key)...")
    
    oracle_queries = 0
    
    # Execute Attack
    recovered_bytes = padding_oracle_attack(iv, ciphertext)
    
    print("\n" + "="*40)
    print("DELIVERABLES")
    print("="*40)
    print(f"1. Recovered Plaintext: '{recovered_bytes.decode('utf-8')}'")
    print(f"2. Total Oracle Queries: {oracle_queries}")
    print("="*40)