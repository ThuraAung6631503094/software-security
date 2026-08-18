import os
import secrets
from argon2 import PasswordHasher
from Crypto.Cipher import AES

ph = PasswordHasher()


def store_password(pw: str) -> str:
    return ph.hash(pw)


def verify_password(hash_: str, pw: str) -> bool:
    try:
        return ph.verify(hash_, pw)
    except Exception:
        return False


def encrypt_gcm(data: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return nonce, ciphertext, tag


def reset_token() -> str:
    return secrets.token_urlsafe(16)


if __name__ == "__main__":
    password = "Week3SecurePassword!"

    stored = store_password(password)

    print("Password hash:", stored)
    print("Password verified:", verify_password(stored, password))

    key = bytes.fromhex(os.environ["ENC_KEY_HEX"])

    nonce, ciphertext, tag = encrypt_gcm(
        b"Software Security Week 3",
        key
    )

    print("Nonce:", nonce.hex())
    print("Ciphertext:", ciphertext.hex())
    print("Auth tag:", tag.hex())

    token = reset_token()
    print("Reset token:", token)