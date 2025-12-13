import hashlib
import hmac
import bcrypt
import base64
import random 
import string
from argon2 import PasswordHasher

argon2_hasher = PasswordHasher(time_cost=1, memory_cost=65536, parallelism=1)
BCRYPT_COST = 12

def random_salt(length=8):
    return ''.join(
        random.choices(string.ascii_letters + string.digits, k=length)
    )

def sha256_hash(password: str, salt: str = "", pepper: str = "") -> str:
    data = (password + salt + pepper).encode("utf-8")
    return hashlib.sha256(data).hexdigest()

def sha256_check(pw_hash: str, password: str, salt: str = "", pepper: str = "") -> bool:
        expected = sha256_hash(password, salt, pepper)
        return hmac.compare_digest(expected, pw_hash)

def bcrypt_hash(password: str, bcrypt_cost, pepper="") -> str:
    data = (password + pepper).encode("utf-8")
    return base64.b64encode(bcrypt.hashpw(data, bcrypt.gensalt(rounds=bcrypt_cost)))


def bcrypt_check(pw_hash_b64: str, password: str, pepper="") -> bool:
    data = (password + pepper).encode("utf-8")
    pw_hash = base64.b64decode(pw_hash_b64)
    return bcrypt.checkpw(data, pw_hash)


def argon2_hash(password: str, pepper="") -> str:
    data = (password + pepper).encode("utf-8")
    return argon2_hasher.hash(data)


def argon2_check(pw_hash: str, password: str, pepper="") -> bool:
    try:
        data = (password + pepper).encode("utf-8")
        return argon2_hasher.verify(pw_hash, data)
    except Exception:
        return False


def verify_password(password: str, stored_hash, mode: str, salt: str = None, pepper: str = ""):
    if mode == "sha256":
        expected = sha256_hash(password, salt, pepper)
        return hmac.compare_digest(expected, stored_hash)
    elif mode == "bcrypt":
        return bcrypt_check(password, stored_hash, pepper)
    elif mode == "argon2":
        return argon2_check(password, stored_hash, pepper)
    else:
        return False
