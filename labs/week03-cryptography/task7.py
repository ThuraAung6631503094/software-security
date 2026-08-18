import os
from Crypto.Cipher import AES

# Get key from environment variable
key = os.environ["AES_KEY"].encode()

message = b"Software Security Week 3"

# -------------------------
# ENCRYPT
# -------------------------

# Random 12-byte nonce
nonce = os.urandom(12)

cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

ciphertext, tag = cipher.encrypt_and_digest(message)

print("Original message:", message.decode())
print("Nonce:", nonce.hex())
print("Ciphertext:", ciphertext.hex())
print("Tag:", tag.hex())


# -------------------------
# DECRYPT
# -------------------------

cipher2 = AES.new(key, AES.MODE_GCM, nonce=nonce)

plaintext = cipher2.decrypt_and_verify(ciphertext, tag)

print("\nDecrypted message:", plaintext.decode())
print("Round-trip: SUCCESS")


# -------------------------
# TAMPER TEST
# -------------------------

tampered = bytearray(ciphertext)

# Flip one ciphertext byte
tampered[0] ^= 1

print("\nTampered ciphertext:", bytes(tampered).hex())

try:
    cipher3 = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher3.decrypt_and_verify(bytes(tampered), tag)

    print("Tamper test: FAILED - modification was not detected")

except ValueError:
    print("Tamper test: SUCCESS")
    print("Decryption failed: MAC check failed")