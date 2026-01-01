import hashlib
import hmac
import bcrypt
import base64
import random 
import string
import argon2


class HashUtils(object):
    def __init__(self, config):
        self.argon2_hasher = argon2.PasswordHasher(time_cost=config['ARGON2_TIME'], 
                                                   memory_cost=config['ARGON2_MEMORY_COST'], 
                                                   parallelism=config['ARGON2_PARALLEL'])
        
        self.bcrypt_cost = config['BCRYPT_COST']

    @staticmethod
    def random_salt(length=8):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    @staticmethod
    def sha256_hash(password: str, salt: str = "", pepper: str = "") -> str:
        data = (password + salt + pepper).encode("utf-8")
        return hashlib.sha256(data).hexdigest()


    def sha256_check(self, pw_hash: str, password: str, salt: str = "", pepper: str = "") -> bool:
            expected = self.sha256_hash(password, salt, pepper)
            return hmac.compare_digest(expected, pw_hash)

    def bcrypt_hash(self, password: str, pepper="") -> str:
        data = (password + pepper).encode("utf-8")
        return base64.b64encode(bcrypt.hashpw(data, bcrypt.gensalt(rounds=self.bcrypt_cost)))

    @staticmethod
    def bcrypt_check(pw_hash_b64: str, password: str, pepper="") -> bool:
        data = (password + pepper).encode("utf-8")
        pw_hash = base64.b64decode(pw_hash_b64)
        return bcrypt.checkpw(data, pw_hash)


    def argon2_hash(self, password: str, pepper="") -> str:
        data = (password + pepper).encode("utf-8")
        return self.argon2_hasher.hash(data)


    def argon2_check(self, pw_hash: str, password: str, pepper="") -> bool:
        try:
            data = (password + pepper).encode("utf-8")
            return self.argon2_hasher.verify(pw_hash, data)
        except Exception:
            return False

