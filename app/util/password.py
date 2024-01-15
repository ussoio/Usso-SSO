"""Password utility functions."""

import base64
import bcrypt
import hashlib


def b64_pwd(password: str | bytes) -> bytes:
    """Return a base64 encoded password hash."""
    if isinstance(password, str):
        password = password.encode("utf-8")
    return base64.b64encode(hashlib.sha3_384(password).digest())


def hash_password(password: str) -> str:
    """Return a salted password hash."""
    b64pwd = b64_pwd(password)
    return bcrypt.hashpw(b64pwd, bcrypt.gensalt())


fake_hash = hash_password("123456")


def check_password(
    password: str | bytes, hashed: bytes = fake_hash
) -> bool:
    """Return True if password matches the hashed password."""
    b64pwd = b64_pwd(password)
    return bcrypt.checkpw(b64pwd, hashed)
