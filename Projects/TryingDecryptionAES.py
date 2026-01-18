"""
TryingDecryptionAES.py
---------------------------------
Educational script to demonstrate how AES (Fernet) decryption
behaves when different keys are tried against encrypted data.

⚠️ For learning & lab use only.
⚠️ Do NOT use on real or unauthorized data.
"""

from cryptography.fernet import Fernet, InvalidToken

# =========================
# INPUT SECTION
# =========================

# Encrypted message (ciphertext)
# Example: encrypt "hello" using Fernet first
encrypted_message = b"PASTE_ENCRYPTED_TEXT_HERE"

# List of keys to try (Base64-encoded Fernet keys)
key_list = [
    b"WRONG_KEY_1",
    b"WRONG_KEY_2",
    b"PASTE_CORRECT_KEY_HERE",
]

# =========================
# DECRYPTION ATTEMPT LOGIC
# =========================

print("[*] Starting AES decryption attempts...\n")

found = False

for index, key in enumerate(key_list, start=1):
    print(f"[+] Trying key {index}...")

    try:
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted_message)
        print("\n✅ SUCCESS!")
        print(f"[✔] Correct Key Found: {key.decode()}")
        print(f"[✔] Decrypted Message: {decrypted.decode()}")
        found = True
        break

    except InvalidToken:
        print("[-] Failed: Invalid key\n")

if not found:
    print("❌ Decryption failed with all provided keys.")

print("\n[*] Process completed.")
