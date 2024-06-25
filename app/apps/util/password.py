"""Password utility functions."""

import base64
import hashlib

import bcrypt
from password_strength import PasswordPolicy


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


def check_password(password: str | bytes, hashed: bytes = fake_hash) -> bool:
    """Return True if password matches the hashed password."""
    b64pwd = b64_pwd(password)
    return bcrypt.checkpw(b64pwd, hashed)


pass_messages = {
    "password_length": "Password must be at least 8 characters long",
    "password_uppercase": "Password must contain at least one uppercase letter",
    "password_lowercase": "Password must contain at least one lowercase letter",
    "password_numbers": "Password must contain at least one number",
    "password_special": "Password must contain at least one special character",
    "password_entropy": "Password must be stronger",
    "password_strength": "Password must be stronger",
}


def check_password_strength(password: str) -> bool:
    """Return True if password is strong enough."""
    policy = PasswordPolicy.from_names(length=8, uppercase=1, strength=0.33)
    errors = []
    for test in policy.test(password):
        test = str(test)
        key = f'password_{test[: test.index("(")].lower()}'
        errors.append((key, pass_messages[key]))
    return errors


def main():
    """
    Main function.
    """
    # password = input("Enter password: ")
    password = "m"
    print(check_password_strength(password))


if __name__ == "__main__":
    main()
