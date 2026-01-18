"""
TryingDecryptionAES.py
---------------------------------
Educational script to demonstrate AES (Fernet) decryption behavior
with invalid keys, wrong keys, and the correct key.

For learning & lab use only.
"""

from cryptography.fernet import Fernet, InvalidToken

# =========================
# INPUT SECTION
# =========================

# Paste encrypted message here (bytes)
encrypted_message = b"PASTE_ENCRYPTED_TEXT_HERE"

# List of keys to try (some invalid, some valid-format)
key_list = [
    b"WRONG_KEY_1",                     # Invalid format
    b"WRONG_KEY_2",                     # Invalid format
    b"PASTE_CORRECT_FERNET_KEY_HERE",   # Valid key
]

# =========================
# DECRYPTION ATTEMPT LOGIC
# =========================

print("[*] Starting AES decryption attempts...\n")

found = False

for index, key in enumerate(key_list, start=1):
    print(f"[+] Trying key {index}...")

    try:
        # Step 1: Try creating Fernet object (format validation)
        fernet = Fernet(key)

        # Step 2: Try decrypting
        decrypted = fernet.decrypt(encrypted_message)

        print("\n✅ SUCCESS!")
        print(f"[✔] Correct Key Found: {key.decode()}")
        print(f"[✔] Decrypted Message: {decrypted.decode()}")
        found = True
        break

    except ValueError:
        print("[-] Failed: Invalid key format (not valid Base64 Fernet key)\n")

    except InvalidToken:
        print("[-] Failed: Valid key format but incorrect key\n")

if not found:
    print("❌ Decryption failed with all provided keys.")

print("[*] Process completed.")
