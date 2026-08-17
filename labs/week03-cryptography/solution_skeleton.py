"""
Week 3 — FIX the misuse here. Fill in the TODOs.
pip install argon2-cffi pycryptodome
"""
import os
import hashlib
import hmac
import re

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError
from Crypto.Cipher import AES

ph = PasswordHasher()


# Store all NEW passwords with Argon2id
def store_password(pw: str) -> str:
    return ph.hash(pw)


# Verify an Argon2id password
def verify_password(hash_: str, pw: str) -> bool:
    try:
        return ph.verify(hash_, pw)
    except (VerificationError, InvalidHashError):
        return False


# Detect an old MD5 hash
def is_legacy_md5(hash_: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{32}", hash_))


# Rehash-on-login migration
def verify_and_upgrade(hash_: str, pw: str):
    # Old MD5 password
    if is_legacy_md5(hash_):
        md5_candidate = hashlib.md5(pw.encode()).hexdigest()

        if not hmac.compare_digest(md5_candidate, hash_.lower()):
            return False, hash_

        # Correct password -> replace MD5 with Argon2id
        new_hash = store_password(pw)
        return True, new_hash

    # Already Argon2id
    if verify_password(hash_, pw):
        if ph.check_needs_rehash(hash_):
            return True, store_password(pw)

        return True, hash_

    return False, hash_


def encrypt_gcm(data: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(data)
    return nonce, ct, tag


def reset_token() -> str:
    import secrets
    return secrets.token_urlsafe(16)


if __name__ == "__main__":
    # Simulate an OLD MD5 database record
    old_hash = hashlib.md5(b"password123").hexdigest()

    print("Before login:", old_hash)

    ok, upgraded_hash = verify_and_upgrade(old_hash, "password123")

    print("Login successful:", ok)
    print("After login:", upgraded_hash)
    print("Uses Argon2id:", upgraded_hash.startswith("$argon2id$"))

    # Verify the new Argon2id hash
    print("Argon2 verify:", verify_password(upgraded_hash, "password123"))