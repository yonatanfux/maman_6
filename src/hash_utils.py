import hashlib
import hmac
import bcrypt

from argon2 import PasswordHasher

argon2_hasher = PasswordHasher(time_cost=1, memory_cost=65536, parallelism=1)

BCRYPT_COST = 12


def sha256_hash(password: str, salt: str, pepper: str = "") -> str:
    data = (password + salt + pepper).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def bcrypt_hash(password: str, bcrypt_cost) -> bytes:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=bcrypt_cost))


def bcrypt_check(password: str, pw_hash: bytes) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), pw_hash)


def argon2_hash(password: str) -> str:
    return argon2_hasher.hash(password)


def argon2_check(password: str, pw_hash: str) -> bool:
    try:
        return argon2_hasher.verify(pw_hash, password)
    except Exception:
        return False


def hash_password(password: str, mode: str, salt: str = None, pepper: str = ""):
    if mode == "sha256":
        if not salt:
            raise ValueError("salt required for sha256 mode")
        return sha256_hash(password, salt, pepper)
    elif mode == "bcrypt":
        return bcrypt_hash(password, BCRYPT_COST)
    elif mode == "argon2":
        return argon2_hash(password)
    else:
        raise ValueError("unsupported hash mode")


def verify_password(password: str, stored_hash, mode: str, salt: str = None, pepper: str = ""):
    if mode == "sha256":
        expected = sha256_hash(password, salt, pepper)
        return hmac.compare_digest(expected, stored_hash)
    elif mode == "bcrypt":
        return bcrypt_check(password, stored_hash)
    elif mode == "argon2":
        return argon2_check(password, stored_hash)
    else:
        return False
