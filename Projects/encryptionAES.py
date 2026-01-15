from cryptography.fernet import Fernet

# Generate a secret key
key = Fernet.generate_key()
fernet = Fernet(key)

print("=== Simple Encryption Tool ===")
print("Secret Key (save this):")
print(key.decode())

# Encrypt
message = input("\nEnter message to encrypt: ")
encrypted = fernet.encrypt(message.encode())
print("\nEncrypted text:")
print(encrypted.decode())

# Decrypt
encrypted_input = input("\nPaste encrypted text to decrypt: ")
decrypted = fernet.decrypt(encrypted_input.encode())
print("\nDecrypted text:")
print(decrypted.decode())
