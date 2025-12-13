import time
import json
import secrets
import pyotp
import argparse

from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify

from src.sql_manager import SqlManager
from src.manage_hash import ManageHash

with open("config.json", 'r') as f:
    config = json.loads(f.read())

hash_mode = config["HASH_MODE"]

sql_manager = SqlManager(config['DB_PATH'])
hash_manager = ManageHash(config['DB_PATH'], hash_mode, config['GLOBAL_PEPPER'])
app = Flask(__name__)

rate_counters = dict()
failed_counters = dict()
current_captcha = secrets.token_urlsafe(16)


class DefenseConfig:
    def __init__(self):
        self.no_defense = False
        self.totp = False
        self.captcha = False
        self.rate_limit = False
        self.account_lock = False

    def to_protection_flags(self):
        return [
            i for i in [self.no_defense, self.totp, self.captcha, self.rate_limit, self.account_lock]
            if i
        ]

    def __str__(self):
        return json.dumps({
            "no_defense": self.no_defense,
            "totp": self.totp,
            "captcha": self.captcha,
            "rate_limit": self.rate_limit,
            "account_lock": self.account_lock
        })


defense_config = DefenseConfig()

with open(config['USERS_PATH'], 'r', encoding='utf-8') as f:
    for user in json.load(f):
        totp_secret = pyotp.random_base32()
        res = hash_manager.add_user(user['username'], user['password'], totp_secret, user['salt'])


def log_attempt(group_seed, username, hash_mode, protection_flags, result, latency_ms):
    # entry = {
    #     "timestamp": datetime.utcnow().isoformat() + "Z",
    #     "group_seed": group_seed,
    #     "username": username,
    #     "hash_mode": hash_mode,
    #     "protection_flags": protection_flags,
    #     "result": result,
    #     "latency_ms": latency_ms
    # }
    entry = [
        datetime.now(timezone.utc).isoformat() + "Z",
        group_seed,
        username,
        hash_mode,
        protection_flags,
        result,
        latency_ms
    ]

    with open(config["ATTEMPTS_LOG"], "a", encoding="utf-8") as f:
        f.write(",".join(entry))


def rate_limit_key():
    ip = request.remote_addr or "unknown"
    return f"ip:{ip}"


def check_rate_limit():
    key = rate_limit_key()
    now = time.time()
    window = 60
    rec = rate_counters.get(key)
    if rec is None or rec[1] + window <= now:
        rate_counters[key] = [1, now]
        return False
    else:
        rec[0] += 1
        rate_counters[key] = rec
        if rec[0] > config["RATE_LIMIT_PER_MIN"]:
            return True
        return False


def is_locked(username):
    user = sql_manager.get_user_by_username(username)
    if not user:
        return False
    locked_until = user["locked_until"]
    if locked_until:
        try:
            dt = datetime.fromisoformat(locked_until)
        except Exception:
            return False
        if dt > datetime.utcnow():
            return True
    return False


def register_failed(username):
    user = sql_manager.get_user_by_username(username)
    if user:
        fails = user["failed_attempts"] + 1
        lock_until = None
        if fails >= config["LOCKOUT_THRESHOLD"]:
            lock_until = (datetime.now(timezone.utc) + timedelta(seconds=config["LOCKOUT_SECONDS"])).isoformat()
            fails = 0

        sql_manager.update_user_by_username(username, failed_attempts=fails, locked_until=lock_until)


def reset_failed(username):
    sql_manager.update_user_by_username(username, failed_attempts=0, locked_until=None)


def captcha_required_for(username):
    username = sql_manager.get_user_by_username(username)
    if not username:
        return False
    return username["failed_attempts"] >= config["CAPTCHA_AFTER"]


@app.route("/register", methods=["POST"])
def register():
    start = time.time()
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    group_seed = data.get("group_seed", config['GROUP_SEED'])

    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

    totp_secret = pyotp.random_base32()
    res = hash_manager.add_user(username, password, totp_secret)
    if res:
        latency_ms = int((time.time() - start) * 1000)
        log_attempt(group_seed, username, hash_mode, ["register"], "success", latency_ms)
        return jsonify({"status": "registered", "totp_secret": totp_secret}), 201
    else:
        latency_ms = int((time.time() - start) * 1000)
        log_attempt(group_seed, username, hash_mode, ["register"], "failure", latency_ms)
        return jsonify({"error": "internal error"}), 500


@app.route("/login", methods=["POST"])
def login():
    start = time.time()
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    group_seed = data.get("group_seed", config['GROUP_SEED'])

    protection_flags = defense_config.to_protection_flags()

    if defense_config.rate_limit:
        if check_rate_limit():
            latency_ms = int((time.time() - start) * 1000)
            log_attempt(group_seed, username, None, ["rate_limit"], "failure", latency_ms)
            return jsonify({"error": "rate limit exceeded"}), 429

    row = sql_manager.get_user_by_username(username)
    if not row:
        latency_ms = int((time.time() - start) * 1000)
        log_attempt(group_seed, username, None, protection_flags, "failure", latency_ms)
        return jsonify({"error": "invalid credentials"}), 401

    if defense_config.account_lock:
        if is_locked(username):
            latency_ms = int((time.time() - start) * 1000)
            log_attempt(group_seed, username, hash_mode, protection_flags, "locked", latency_ms)
            return jsonify({"error": "account locked"}), 403

    if defense_config.captcha:
        if captcha_required_for(username):
            captcha_token = data.get("captcha_token", None)
            if captcha_token == current_captcha:
                reset_failed(username)
            else:
                latency_ms = int((time.time() - start) * 1000)
                log_attempt(group_seed, username, hash_mode, protection_flags, "captcha_required",
                            latency_ms)
                return jsonify({"captcha_required": True}), 403

    ok = hash_manager.login(username, password)
    latency_ms = int((time.time() - start) * 1000)
    if ok:
        reset_failed(username)
        if defense_config.totp:
            log_attempt(group_seed, username, hash_mode, protection_flags, "partial_success", latency_ms)
            return jsonify({"status": "ok, move to /login_totp"}), 200
        else:
            log_attempt(group_seed, username, hash_mode, protection_flags, "success", latency_ms)
            return jsonify({"status": "ok"}), 200
    else:
        register_failed(username)
        log_attempt(group_seed, username, hash_mode, protection_flags, "failure", latency_ms)
        return jsonify({"error": "invalid credentials"}), 401


@app.route("/login_totp", methods=["POST"])
def login_totp():
    if not defense_config.totp:
        return jsonify({"error": "totp isn't configured in server"}), 405
    start = time.time()
    data = request.get_json() or {}
    username = data.get("username")
    totp_token = data.get("totp_token")
    group_seed = data.get("group_seed", config['GROUP_SEED'])

    protection_flags = defense_config.to_protection_flags()
    user = sql_manager.get_user_by_username(username)
    if not user or not user["totp_secret"]:
        latency_ms = int((time.time() - start) * 1000)
        log_attempt(group_seed, username, None, protection_flags, "failure", latency_ms)
        return jsonify({"error": "unknown user or no totp configured"}), 401

    totp = pyotp.TOTP(user["totp_secret"])
    try:
        ok = totp.verify(str(totp_token), valid_window=1)
    except Exception:
        ok = False

    latency_ms = int((time.time() - start) * 1000)
    if ok:
        reset_failed(username)
        log_attempt(group_seed, username, None, protection_flags, "success", latency_ms)
        return jsonify({"status": "ok"}), 200
    else:
        register_failed(username)
        log_attempt(group_seed, username, None, protection_flags, "failure", latency_ms)
        return jsonify({"error": "invalid totp"}), 401


@app.route("/admin/get_captcha_token", methods=["GET"])
def get_captcha_token():
    global current_captcha
    group_seed = request.args.get("group_seed", "")
    if group_seed != config['GROUP_SEED']:
        return jsonify({"error": "unauthorized"}), 403
    token = secrets.token_urlsafe(16)
    current_captcha = token
    return jsonify({"captcha_token": token}), 200


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--defense",
        required=True,
        nargs="+",
        choices=[
            "no-defense",
            "totp",
            "captcha",
            "rate-limit",
            "account_lock",
        ],
        help="Defense mechanism to enable"
    )

    parser.add_argument(
        "--hash-mode",
        required=True,
        choices=[
            "SHA_PLAIN",
            "SHA_SALT",
            "SHA_PEPPER",
            "SHA_SALT_PEPPER",
            "BCRYPT",
            "BCRYPT_PEPPER",
            "ARGON2",
            "ARGON2_PEPPER"
        ],
        help="Hash mode to use"
    )

    args = parser.parse_args()

    defense_cfg = DefenseConfig()

    if "no-defense" in args.defense:
        defense_cfg.no_defense = True
        return defense_cfg

    defense_cfg.totp = "totp" in args.defense
    defense_cfg.captcha = "captcha" in args.defense
    defense_cfg.rate_limit = "rate-limit" in args.defense
    defense_cfg.account_lock = "account_lock" in args.defense

    return defense_cfg, args.hash_mode


def main():
    global defense_config, hash_mode
    defense_config, hash_mode = parse_args()
    print(defense_config)
    print(hash_mode)
    app.run(host="0.0.0.0", port=5000, debug=True)


if __name__ == "__main__":
    main()
