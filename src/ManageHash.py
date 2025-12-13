import json
import hash_utils
from sql_manager import SqlManager

class ManageHash(object):

    def __init__(self, DB_PATH, mode, pepper):
        self._sql = SqlManager(DB_PATH)
        self._mode = mode
        self._PEPPER = pepper

    def load_users(self, PATH):

        with open(PATH, "r", encoding="utf-8") as f:
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

    def add_user(self, username, password, salt=None):
        
        if self._mode in ['SHA_SALT', 'SHA_SALT_PEPPER'] and salt is None:
            salt = hash_utils.random_salt()
        else:
            salt = ''
        
        password_hash = self._hash(password, salt, self._PEPPER)
        res = self._sql.insert_user(username, password_hash, salt)
        if res:
            return {'code': 200}
        else:
            return {'code': 401}


    def login(self, username, given_password):
        user = self._sql.get_user_by_username(username)
        if user is None:
            return {'code': 404, 'msg': 'No such user exists'}
        
        return self._check_hash(user['password_hash'], given_password, user['salt'], self._PEPPER)