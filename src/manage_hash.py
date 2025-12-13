import json
from src import hash_utils
from src.sql_manager import SqlManager


class ManageHash(object):

    def __init__(self, db_path, mode, pepper):
        self._sql = SqlManager(db_path)
        self._mode = mode
        self._PEPPER = pepper

    def load_users(self, path):

        with open(path, "r", encoding="utf-8") as f:
            for user in json.load(f):
                self.add_user(user['username'], user['password'], user['salt'])

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

    def _check_hash(self, hash, password, salt, pepper):
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

    def add_user(self, username, password, totp_secret, salt=None):

        if self._mode in ['SHA_SALT', 'SHA_SALT_PEPPER'] and salt is None:
            salt = hash_utils.random_salt()
        else:
            salt = ''

        password_hash = self._hash(password, salt, self._PEPPER)
        return self._sql.insert_user(username, password_hash, salt, totp_secret)

    def login(self, username, given_password):
        user = self._sql.get_user_by_username(username)
        if user is None:
            return {'code': 404, 'msg': 'No such user exists'}

        return self._check_hash(user['password_hash'], given_password, user['salt'], self._PEPPER)
