import time
import json
import secrets
import pyotp
import logging

from datetime import datetime, timedelta, timezone

#from src.self._sql_manager import SqlManager
from src.in_memory_db import SqlManager
from src.manage_hash import ManageHash
from src.defense_config import DefenseConfig

class Server(object):

    def __init__(self, defense_config: list, hash_mode: str, run_mode: str):
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s | %(levelname)s | %(name)s | %(message)s"
        )

        self._logger = logging.getLogger(__name__)
        werkzeug_logger = logging.getLogger('werkzeug')
        werkzeug_logger.setLevel(logging.ERROR)

        with open("config.json", 'r') as f:
            self._config = json.loads(f.read())

        self._defense_config = DefenseConfig(defense_config)
        self._hash_mode = hash_mode
        self._sql_manager = SqlManager(self._config['DB_PATH'])
        self._hash_manager = ManageHash(hash_mode, self._config)

        # Create log with a file name according to the run mode, hash mode and defense flags
        logfile_name = self._config["ATTEMPTS_LOG_PREFIX"] + "__" + run_mode + "__" + str(self._defense_config) \
        + "__" + str.lower(self._hash_mode) + '.log'

        self._attempts_file = open(logfile_name, "a", encoding="utf-8")

        self._rate_counters = dict()
        self._current_captcha = secrets.token_urlsafe(16)

        with open(self._config['USERS_PATH'], 'r', encoding='utf-8') as f:
            for user in json.load(f)["users"]:
                res = self.add_user(user['username'], user['password'], user['sha_salt'], user['totp_secret'])

        self._logger.info(f"Running, defense_config={str(defense_config)}, {hash_mode=}")


    def add_user(self, username, password, input_salt=None, totp_secret=None):
        if not totp_secret:
            totp_secret = pyotp.random_base32()
        salt, password_hash = self._hash_manager.create_hash_password(password, input_salt)
        return self._sql_manager.insert_user(username, password_hash, salt, totp_secret)

    def log_attempt(self, group_seed, username, hash_mode, protection_flags, result, latency_ms):
        entry = [
            datetime.now(timezone.utc).isoformat() + "Z",
            group_seed,
            username,
            hash_mode,
            protection_flags,
            result,
            latency_ms
        ]

        self._attempts_file.write(",".join([str(i) for i in entry]) + "\n")

    @staticmethod
    def rate_limit_key():
        ip = "local"
        return f"ip:{ip}"


    def check_rate_limit(self):
        key = self.rate_limit_key()
        now = time.time()
        window = 60
        rec = self._rate_counters.get(key)
        if rec is None or rec[1] + window <= now:
            self._rate_counters[key] = [1, now]
            return False
        else:
            rec[0] += 1
            self._rate_counters[key] = rec
            if rec[0] > self._config["RATE_LIMIT_PER_MIN"]:
                return True
            return False


    def is_locked(self, username):
        user = self._sql_manager.get_user_by_username(username)
        if not user:
            return False
        locked_until = user["locked_until"]
        if locked_until:
            try:
                dt = datetime.fromisoformat(locked_until)
            except Exception:
                return False
            if dt > datetime.now(timezone.utc):
                return True
        return False


    def register_failed(self, username):
        user = self._sql_manager.get_user_by_username(username)
        if user:
            fails = user["failed_attempts"] + 1
            lock_until = None
            if self._defense_config.account_lock and fails >= self._config["LOCKOUT_THRESHOLD"]:
                lock_until = (datetime.now(timezone.utc) + timedelta(seconds=self._config["LOCKOUT_SECONDS"])).isoformat()
                fails = 0

            self._sql_manager.update_user_by_username(username, failed_attempts=fails, locked_until=lock_until)


    def reset_failed(self, username):
        self._sql_manager.update_user_by_username(username, failed_attempts=0, locked_until=None)


    def captcha_required_for(self, username):
        username_sql = self._sql_manager.get_user_by_username(username)
        if not username_sql:
            return False
        return username_sql["failed_attempts"] >= self._config["CAPTCHA_AFTER"]


    #@app.route("/register", methods=["POST"])
    def register(self, username, password, group_seed=None):
        start = time.time()
        
        if group_seed is None:
            group_seed = self._config['GROUP_SEED']

        if not username or not password:
            return {"error": "username and password required"}, 400

        res = self.add_user(username, password)
        if res:
            latency_ms = int((time.time() - start) * 1000)
            self.log_attempt(group_seed, username, self._hash_mode, ["register"], "success", latency_ms)
            return {"status": "registered"}, 201
        else:
            latency_ms = int((time.time() - start) * 1000)
            self.log_attempt(group_seed, username, self._hash_mode, ["register"], "failure", latency_ms)
            return {"error": "internal error"}, 500


    #@app.route("/login", methods=["POST"])
    def login(self, username, password, captcha_token=None, group_seed=None):
        start = time.time()
        if group_seed is None:
            group_seed = self._config['GROUP_SEED']

        protection_flags = self._defense_config.to_protection_flags()

        if self._defense_config.rate_limit:
            if self.check_rate_limit():
                latency_ms = int((time.time() - start) * 1000)
                self.log_attempt(group_seed, username, None, ["rate_limit"], "failure", latency_ms)
                return {"error": "rate limit exceeded"}, 429

        row = self._sql_manager.get_user_by_username(username)
        if not row:
            return {"error": "user does not exist"}, 404

        if self._defense_config.account_lock:
            if self.is_locked(username):
                latency_ms = int((time.time() - start) * 1000)
                self.log_attempt(group_seed, username, self._hash_mode, protection_flags, "locked", latency_ms)
                return {"error": "account locked"}, 403

        if self._defense_config.captcha:
            if self.captcha_required_for(username):
                if captcha_token is not None and captcha_token == self._current_captcha:
                    self.reset_failed(username)
                else:
                    latency_ms = int((time.time() - start) * 1000)
                    self.log_attempt(group_seed, username, self._hash_mode, protection_flags, "captcha_required",
                                latency_ms)
                    return {"captcha_required": True}, 403

        # Test login's password
        user = self._sql_manager.get_user_by_username(username)
        if user is None:
            return {"status": "no such user exists"}, 404
        ok = self._hash_manager.check_hash(user['password_hash'], password, user['salt'])

        latency_ms = int((time.time() - start) * 1000)
        if ok:
            self.reset_failed(username)
            if self._defense_config.totp:
                self.log_attempt(group_seed, username, self._hash_mode, protection_flags, "partial_success", latency_ms)
                return {"status": "ok, move to /login_totp"}, 301
            else:
                self.log_attempt(group_seed, username, self._hash_mode, protection_flags, "success", latency_ms)
                return {"status": "ok"}, 200
        else:
            self.register_failed(username)
            self.log_attempt(group_seed, username, self._hash_mode, protection_flags, "failure", latency_ms)
            return {"error": "invalid credentials"}, 401


    # @app.route("/login_totp", methods=["POST"])
    def login_totp(self, username, totp_token, group_seed=None):
        if not self._defense_config.totp:
            return {"error": "totp isn't configured in server"}, 405
        start = time.time()
        if group_seed is None:
            group_seed = self._config['GROUP_SEED']

        protection_flags = self._defense_config.to_protection_flags()
        user = self._sql_manager.get_user_by_username(username)
        if not user or not user["totp_secret"]:
            latency_ms = int((time.time() - start) * 1000)
            self.log_attempt(group_seed, username, None, protection_flags, "failure", latency_ms)
            return {"error": "unknown user or no totp configured"}, 401

        totp = pyotp.TOTP(user["totp_secret"])
        try:
            ok = totp.verify(str(totp_token), valid_window=1)
        except Exception:
            ok = False

        latency_ms = int((time.time() - start) * 1000)
        if ok:
            self.reset_failed(username)
            self.log_attempt(group_seed, username, None, protection_flags, "success", latency_ms)
            return {"status": "ok"}, 200
        else:
            self.register_failed(username)
            self.log_attempt(group_seed, username, None, protection_flags, "failure", latency_ms)
            return {"error": "invalid totp"}, 401


    #@app.route("/admin/get_captcha_token", methods=["GET"])
    def get_captcha_token(self, group_seed):
        if group_seed != self._config['GROUP_SEED']:
            return {"error": "unauthorized"}, 403
        token = secrets.token_urlsafe(16)
        self._current_captcha = token
        return {"captcha_token": token}, 200


    def __del__(self):
        self._attempts_file.close()

# if __name__ == "__main__":
    # main()
