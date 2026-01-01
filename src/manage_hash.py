from src.hash_utils import HashUtils

class ManageHash(object):

    def __init__(self, mode, config):
        self._mode = mode
        self._PEPPER = ''
        if self._mode in ['SHA_PEPPER', 'SHA_SALT_PEPPER', 'BCRYPT_PEPPER', 'ARGON2_PEPPER']:
            self._PEPPER = config['GLOBAL_PEPPER']

        self.hash_utils = HashUtils(config)

    def _hash(self, password, salt, pepper):
        if self._mode == 'SHA_PLAIN':
            return self.hash_utils.sha256_hash(password, salt="", pepper="")
        elif self._mode == 'SHA_SALT':
            return self.hash_utils.sha256_hash(password, salt, pepper="")
        elif self._mode == 'SHA_PEPPER':
            return self.hash_utils.sha256_hash(password, salt="", pepper=pepper)
        elif self._mode == 'SHA_SALT_PEPPER':
            return self.hash_utils.sha256_hash(password, salt, pepper)
        elif self._mode == 'BCRYPT':
            return self.hash_utils.bcrypt_hash(password, pepper="")
        elif self._mode == 'BCRYPT_PEPPER':
            return self.hash_utils.bcrypt_hash(password, pepper=pepper)
        elif self._mode == 'ARGON2':
            return self.hash_utils.argon2_hash(password, pepper="")
        elif self._mode == 'ARGON2_PEPPER':
            return self.hash_utils.argon2_hash(password, pepper)
        else:
            raise Exception("Unknown method")

    def check_hash(self, hash, password, salt):
        pepper = self._PEPPER

        if self._mode == 'SHA_PLAIN':
            return self.hash_utils.sha256_check(hash, password, salt="", pepper="")
        elif self._mode == 'SHA_SALT':
            return self.hash_utils.sha256_check(hash, password, salt, pepper="")
        elif self._mode == 'SHA_PEPPER':
            return self.hash_utils.sha256_check(hash, password, salt="", pepper=pepper)
        elif self._mode == 'SHA_SALT_PEPPER':
            return self.hash_utils.sha256_check(hash, password, salt, pepper)
        elif self._mode == 'BCRYPT':
            return self.hash_utils.bcrypt_check(hash, password, pepper="")
        elif self._mode == 'BCRYPT_PEPPER':
            return self.hash_utils.bcrypt_check(hash, password, pepper)
        elif self._mode == 'ARGON2':
            return self.hash_utils.argon2_check(hash, password, pepper="")
        elif self._mode == 'ARGON2_PEPPER':
            return self.hash_utils.argon2_check(hash, password, pepper)


    def create_hash_password(self, password, input_salt=None):

        if self._mode in ['SHA_SALT', 'SHA_SALT_PEPPER'] and input_salt is None:
            salt = HashUtils.random_salt()
        else:
            salt = ''

        password_hash = self._hash(password, salt, self._PEPPER)
        return salt, password_hash
