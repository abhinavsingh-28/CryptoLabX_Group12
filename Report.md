# Padding Oracle Attack Analysis

## 1. Understand the Attack
* **AES-CBC (Cipher Block Chaining)**: A mode of operation for block ciphers where each plaintext block is XORed with the previous ciphertext block before being encrypted. The first block is XORed with an Initialization Vector (IV). 
* **PKCS#7 Padding**: Block ciphers require plaintext to be a multiple of the block size (16 bytes for AES). PKCS#7 adds bytes to the end of the plaintext, where the value of each added byte is equal to the number of bytes added (e.g., if 3 bytes are needed, it appends `\x03\x03\x03`).
* **Padding Oracle**: A vulnerability where a system leaks information about whether a decrypted ciphertext has valid PKCS#7 padding (usually via error messages or timing differences). Attackers use this boolean feedback (True/False) to systematically deduce the plaintext.

## 3. Analyze the Attack
* **Oracle Queries Required**: The script typically requires between 2,000 to 4,000 queries to decrypt a standard short message (average 128 queries per byte).
* **Why Modifying the Previous Block Works**: In CBC decryption, the plaintext of a block ($P_i$) is calculated as $P_i = Decrypt_K(C_i) \oplus C_{i-1}$. If an attacker modifies the previous ciphertext block ($C_{i-1}$), the change directly propagates to the resulting plaintext $P_i$ after decryption. By manipulating $C_{i-1}$ and sending it to the padding oracle, the attacker can deduce the intermediate state ($Decrypt_K(C_i)$) byte by byte.

## 4. Security Recommendation (Prevention)
To prevent padding oracle vulnerabilities in a real system:
1. **Use Authenticated Encryption**: Switch to modes like AES-GCM or ChaCha20-Poly1305, which inherently authenticate the ciphertext and do not rely on padding mechanisms.
2. **Encrypt-then-MAC (EtM)**: If CBC mode must be used, compute a Message Authentication Code (MAC) over the ciphertext. The server must verify the MAC *before* attempting decryption. If the MAC is invalid, reject the request immediately without checking the padding.