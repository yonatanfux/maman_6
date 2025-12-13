import time
import json
import secrets
import pyotp
import argparse

from datetime import datetime, timedelta
from flask import Flask, request, jsonify

from src.sql_manager import SqlManager
from src import consts
from src.hash_utils import *

with open("config.json", 'r') as f:
    config = json.loads(f.read())

hash_mode = config["HASH_MODE"]

sql_manager = SqlManager()

app = Flask(__name__)

rate_counters = {}
failed_counters = {}


class DefenseConfig:
    def __init__(self):
        self.no_defense = False
        self.totp = False
        self.captcha = False
        self.rate_limit = False
        self.account_lock = False

    def to_protection_flags(self):
        return [
            i for i in
            [
                self.no_defense, self.totp, self.captcha, self.rate_limit, self.account_lock
            ]
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
        datetime.utcnow().isoformat() + "Z",
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
    db = sql_manager.get_db()
    c = db.cursor()
    c.execute("SELECT locked_until FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    if not row:
        return False
    locked_until = row["locked_until"]
    if locked_until:
        try:
            dt = datetime.fromisoformat(locked_until)
        except Exception:
            return False
        if dt > datetime.utcnow():
            return True
    return False


def register_failed(username):
    db = sql_manager.get_db()
    c = db.cursor()
    c.execute("SELECT failed_attempts FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    if row:
        fails = row["failed_attempts"] + 1
        lock_until = None
        if fails >= config["LOCKOUT_THRESHOLD"]:
            lock_until = (datetime.utcnow() + timedelta(seconds=config["LOCKOUT_SECONDS"])).isoformat()
            fails = 0
        c.execute("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE username = ?",
                  (fails, lock_until, username))
        db.commit()


def reset_failed(username):
    db = sql_manager.get_db()
    c = db.cursor()
    c.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE username = ?", (username,))
    db.commit()


def captcha_required_for(username):
    db = sql_manager.get_db()
    c = db.cursor()
    c.execute("SELECT failed_attempts FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    if not row:
        return False
    return row["failed_attempts"] >= config["CAPTCHA_AFTER"]


@app.route("/register", methods=["POST"])
def register():
    start = time.time()
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    group_seed = data.get("group_seed", consts.GROUP_SEED)

    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

    salt = None
    if hash_mode == "sha256":
        salt = secrets.token_hex(8)

    totp_secret = pyotp.random_base32()

    try:
        if hash_mode == "sha256":
            stored_hash = hash_password(password, "sha256", salt=salt, pepper=config["GLOBAL_PEPPER"])
        elif hash_mode == "bcrypt":
            stored_hash = hash_password(password, "bcrypt")
            stored_hash = stored_hash.decode("utf-8", errors="ignore")
        elif hash_mode == "argon2":
            stored_hash = hash_password(password, "argon2")
        else:
            return jsonify({"error": "unsupported hash_mode"}), 400

        db = sql_manager.get_db()
        c = db.cursor()
        c.execute("INSERT INTO users (username, hash_mode, password_hash, salt, totp_secret) VALUES (?, ?, ?, ?, ?)",
                  (username, hash_mode, stored_hash, salt, totp_secret))
        db.commit()

        latency_ms = int((time.time() - start) * 1000)
        log_attempt(group_seed, username, hash_mode, ["register"], "success", latency_ms)

        return jsonify({"status": "registered", "totp_secret": totp_secret}), 201

    except Exception as e:
        latency_ms = int((time.time() - start) * 1000)
        log_attempt(group_seed, username, hash_mode, ["register"], "failure", latency_ms)
        return jsonify({"error": "internal error", "detail": str(e)}), 500


@app.route("/login", methods=["POST"])
def login():
    start = time.time()
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    group_seed = data.get("group_seed", consts.GROUP_SEED)

    protection_flags = defense_config.to_protection_flags()

    if defense_config.rate_limit:
        if check_rate_limit():
            latency_ms = int((time.time() - start) * 1000)
            log_attempt(group_seed, username, None, ["rate_limit"], "failure", latency_ms)
            return jsonify({"error": "rate limit exceeded"}), 429

    db = sql_manager.get_db()
    c = db.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = c.fetchone()
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
            latency_ms = int((time.time() - start) * 1000)
            log_attempt(group_seed, username, hash_mode, protection_flags, "captcha_required",
                        latency_ms)
            return jsonify({"captcha_required": True}), 403

    stored_hash = row["password_hash"]
    salt = row["salt"]

    if hash_mode == "bcrypt" and isinstance(stored_hash, str):
        stored_hash_bytes = stored_hash.encode("utf-8")
    else:
        stored_hash_bytes = stored_hash

    ok = False
    try:
        if hash_mode == "sha256":
            ok = verify_password(password, stored_hash, "sha256", salt, pepper=config["GLOBAL_PEPPER"])
        elif hash_mode == "bcrypt":
            ok = verify_password(password, stored_hash_bytes, "bcrypt")
        elif hash_mode == "argon2":
            ok = verify_password(password, stored_hash, "argon2")
    except Exception:
        ok = False

    latency_ms = int((time.time() - start) * 1000)
    if ok:
        reset_failed(username)
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
    group_seed = data.get("group_seed", consts.GROUP_SEED)

    protection_flags = defense_config.to_protection_flags()
    db = sql_manager.get_db()
    c = db.cursor()
    c.execute("SELECT totp_secret FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    if not row or not row["totp_secret"]:
        latency_ms = int((time.time() - start) * 1000)
        log_attempt(group_seed, username, None, protection_flags, "failure", latency_ms)
        return jsonify({"error": "unknown user or no totp configured"}), 401

    totp = pyotp.TOTP(row["totp_secret"])
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
    group_seed = request.args.get("group_seed", "")
    if group_seed != consts.GROUP_SEED:
        return jsonify({"error": "unauthorized"}), 403
    token = secrets.token_urlsafe(16)
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

    args = parser.parse_args()

    cfg = DefenseConfig()

    if "no-defense" in args.defense:
        cfg.no_defense = True
        return cfg

    cfg.totp = "totp" in args.defense
    cfg.captcha = "captcha" in args.defense
    cfg.rate_limit = "rate-limit" in args.defense
    cfg.account_lock = "account_lock" in args.defense

    return cfg


def main():
    global defense_config
    defense_config = parse_args()
    print(defense_config)
    app.run(host="0.0.0.0", port=5000, debug=True)


if __name__ == "__main__":
    main()
