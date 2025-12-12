import time
import json
import hashlib
import secrets
import hmac
from datetime import datetime, timedelta

from flask import Flask, request, jsonify
import pyotp
import bcrypt
from argon2 import PasswordHasher

from src.sql_manager import SqlManager
from src import consts

with open("config.json", 'r') as f:
    config = json.loads(f.read())

hash_mode = config["HASH_MODE"]

argon2_hasher = PasswordHasher(time_cost=1, memory_cost=65536, parallelism=1)
sql_manager = SqlManager()

app = Flask(__name__)

rate_counters = {}
failed_counters = {}


@app.teardown_appcontext
def close_connection():
    sql_manager.close()


def sha256_hash(password: str, salt: str, pepper: str = "") -> str:
    data = (password + salt + pepper).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def bcrypt_hash(password: str) -> bytes:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=config["BCRYPT_COST"]))


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
        return bcrypt_hash(password)
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


def log_attempt(group_seed, username, hash_mode, protection_flags, result, latency_ms):
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "group_seed": group_seed,
        "username": username,
        "hash_mode": hash_mode,
        "protection_flags": protection_flags,
        "result": result,
        "latency_ms": latency_ms
    }
    with open(config["ATTEMPTS_LOG"], "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


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

    protection_flags = []
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

    if is_locked(username):
        latency_ms = int((time.time() - start) * 1000)
        log_attempt(group_seed, username, hash_mode, protection_flags + ["locked"], "locked", latency_ms)
        return jsonify({"error": "account locked"}), 403

    if captcha_required_for(username):
        latency_ms = int((time.time() - start) * 1000)
        log_attempt(group_seed, username, hash_mode, protection_flags + ["captcha_needed"], "captcha_required",
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
    start = time.time()
    data = request.get_json() or {}
    username = data.get("username")
    totp_token = data.get("totp_token")
    group_seed = data.get("group_seed", consts.GROUP_SEED)

    protection_flags = ["totp"]
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


if __name__ == "__main__":
    sql_manager.connect()
    app.run(host="0.0.0.0", port=5000, debug=True)
