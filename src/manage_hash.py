from src import hash_utils

class ManageHash(object):

    def __init__(self, db_path, mode, pepper):
        self._mode = mode
        self._PEPPER = ''
        if self._mode in ['SHA_PEPPER', 'SHA_SALT_PEPPER', 'BCRYPT_PEPPER', 'ARGON2_PEPPER']:
            self._PEPPER = pepper

    def _hash(self, password, salt, pepper):
        if self._mode == 'SHA_PLAIN':
            return hash_utils.sha256_hash(password, salt="", pepper="")
        elif self._mode == 'SHA_SALT':
            return hash_utils.sha256_hash(password, salt, pepper="")
        elif self._mode == 'SHA_PEPPER':
            return hash_utils.sha256_hash(password, salt="", pepper=pepper)
        elif self._mode == 'SHA_SALT_PEPPER':
            return hash_utils.sha256_hash(password, salt, pepper)
        elif self._mode == 'BCRYPT':
            return hash_utils.bcrypt_hash(password, pepper="")
        elif self._mode == 'BCRYPT_PEPPER':
            return hash_utils.bcrypt_hash(password, pepper)
        elif self._mode == 'ARGON2':
            return hash_utils.argon2_hash(password, pepper="")
        elif self._mode == 'ARGON2_PEPPER':
            return hash_utils.argon2_hash(password, pepper)
        else:
            raise Exception("Unknown method")

    def check_hash(self, hash, password, salt):
        pepper = self._PEPPER

        if self._mode == 'SHA_PLAIN':
            return hash_utils.sha256_check(hash, password, salt="", pepper="")
        elif self._mode == 'SHA_SALT':
            return hash_utils.sha256_check(hash, password, salt, pepper="")
        elif self._mode == 'SHA_PEPPER':
            return hash_utils.sha256_check(hash, password, salt="", pepper=pepper)
        elif self._mode == 'SHA_SALT_PEPPER':
            return hash_utils.sha256_check(hash, password, salt, pepper)
        elif self._mode == 'BCRYPT':
            return hash_utils.bcrypt_check(hash, password, pepper="")
        elif self._mode == 'BCRYPT_PEPPER':
            return hash_utils.bcrypt_check(hash, password, pepper)
        elif self._mode == 'ARGON2':
            return hash_utils.argon2_check(hash, password, pepper="")
        elif self._mode == 'ARGON2_PEPPER':
            return hash_utils.argon2_check(hash, password, pepper)


    def create_hash_password(self, password, input_salt=None):

        if self._mode in ['SHA_SALT', 'SHA_SALT_PEPPER'] and input_salt is None:
            salt = hash_utils.random_salt()
        else:
            salt = ''

        password_hash = self._hash(password, salt, self._PEPPER)
        return salt, password_hash
