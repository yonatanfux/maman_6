import time
import json
import secrets

import pyotp
import logging
import uvicorn
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import sqlite3

from datetime import datetime, timedelta, timezone

#from src.sql_manager import SqlManager
from src.in_memory_db import SqlManager
from src.manage_hash import ManageHash
from src.args import parse_args

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s"
)

logger = logging.getLogger(__name__)
werkzeug_logger = logging.getLogger('werkzeug')
werkzeug_logger.setLevel(logging.ERROR)

with open("config.json", 'r') as f:
    config = json.loads(f.read())

# attempts_file = open(config["ATTEMPTS_LOG"], "a", encoding="utf-8")

defense_config, hash_mode = parse_args()
sql_manager = SqlManager(config['DB_PATH'])
hash_manager = ManageHash(config['DB_PATH'], hash_mode, config['GLOBAL_PEPPER'])
app = FastAPI()

rate_counters = dict()
failed_counters = dict()
current_captcha = secrets.token_urlsafe(16)


def add_user(username, password, input_salt=None):
    totp_secret = pyotp.random_base32()
    salt, password_hash = hash_manager.create_hash_password(password, input_salt)
    return sql_manager.insert_user(username, password_hash, salt, totp_secret)


with open(config['USERS_PATH'], 'r', encoding='utf-8') as f:
    for user in json.load(f)["users"]:
        res = add_user(user['username'], user['password'], user['sha_salt'])


def log_attempt(group_seed, username, hash_mode, protection_flags, result, latency_ms):
    entry = [
        datetime.now(timezone.utc).isoformat() + "Z",
        group_seed,
        username,
        hash_mode,
        protection_flags,
        result,
        latency_ms
    ]

    with open(config["ATTEMPTS_LOG"], "a", encoding="utf-8") as attempts_file:
        attempts_file.write(",".join([str(i) for i in entry]) + "\n")


def rate_limit_key(host: str):
    ip = host
    return f"ip:{ip}"


def check_rate_limit(host: str):
    key = rate_limit_key(host)
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


@app.post("/register")
async def register(request: Request):
    start = time.time()
    data = await request.json() or {}
    username = data.get("username")
    password = data.get("password")
    group_seed = data.get("group_seed", config['GROUP_SEED'])

    if not username or not password:
        return JSONResponse({"error": "username and password required"}, status_code=400)

    res = add_user(username, password)
    if res:
        latency_ms = int((time.time() - start) * 1000)
        log_attempt(group_seed, username, hash_mode, ["register"], "success", latency_ms)
        return JSONResponse({"status": "registered"}, status_code=201)
    else:
        latency_ms = int((time.time() - start) * 1000)
        log_attempt(group_seed, username, hash_mode, ["register"], "failure", latency_ms)
        return JSONResponse({"error": "internal error"}, status_code=500) 


@app.post("/login")
async def login(request: Request):
    start = time.time()
    data = await request.json()
    username = data.get("username")
    password = data.get("password")
    group_seed = data.get("group_seed", config['GROUP_SEED'])

    protection_flags = defense_config.to_protection_flags()

    if defense_config.rate_limit:
        if check_rate_limit(request.client.host):
            latency_ms = int((time.time() - start) * 1000)
            log_attempt(group_seed, username, None, ["rate_limit"], "failure", latency_ms)
            return JSONResponse({"error": "rate limit exceeded"}, status_code=429)

    row = sql_manager.get_user_by_username(username)
    if not row:
        return JSONResponse({"error": "user does not exist"}, status_code=404)

    if defense_config.account_lock:
        if is_locked(username):
            latency_ms = int((time.time() - start) * 1000)
            log_attempt(group_seed, username, hash_mode, protection_flags, "locked", latency_ms)
            return JSONResponse({"error": "account locked"}, status_code=403)

    if defense_config.captcha:
        if captcha_required_for(username):
            captcha_token = data.get("captcha_token", None)
            if captcha_token == current_captcha:
                reset_failed(username)
            else:
                latency_ms = int((time.time() - start) * 1000)
                log_attempt(group_seed, username, hash_mode, protection_flags, "captcha_required",
                            latency_ms)
                return JSONResponse({"captcha_required": True}, status_code=403)

    # Test login's password
    user = sql_manager.get_user_by_username(username)
    if user is None:
        return JSONResponse({"status": "no such user exists"}, status_code=404)
    ok = hash_manager.check_hash(user['password_hash'], password, user['salt'])

    latency_ms = int((time.time() - start) * 1000)
    if ok:
        reset_failed(username)
        if defense_config.totp:
            log_attempt(group_seed, username, hash_mode, protection_flags, "partial_success", latency_ms)
            return JSONResponse({"status": "ok, move to /login_totp"}, status_code=301)
        else:
            log_attempt(group_seed, username, hash_mode, protection_flags, "success", latency_ms)
            return JSONResponse({"status": "ok"}, status_code=200)
    else:
        register_failed(username)
        log_attempt(group_seed, username, hash_mode, protection_flags, "failure", latency_ms)
        return JSONResponse({"error": "invalid credentials"}, status_code=401)


@app.post("/login_totp")
async def login_totp(request: Request):
    if not defense_config.totp:
        return JSONResponse({"error": "totp isn't configured in server"}, status_code=405)
    start = time.time()
    data = await request.json() or {}
    username = data.get("username")
    totp_token = data.get("totp_token")
    group_seed = data.get("group_seed", config['GROUP_SEED'])

    protection_flags = defense_config.to_protection_flags()
    user = sql_manager.get_user_by_username(username)
    if not user or not user["totp_secret"]:
        latency_ms = int((time.time() - start) * 1000)
        log_attempt(group_seed, username, None, protection_flags, "failure", latency_ms)
        return JSONResponse({"error": "unknown user or no totp configured"}, status_code=401)

    totp = pyotp.TOTP(user["totp_secret"])
    try:
        ok = totp.verify(str(totp_token), valid_window=1)
    except Exception:
        ok = False

    latency_ms = int((time.time() - start) * 1000)
    if ok:
        reset_failed(username)
        log_attempt(group_seed, username, None, protection_flags, "success", latency_ms)
        return JSONResponse({"status": "ok"})
    else:
        register_failed(username)
        log_attempt(group_seed, username, None, protection_flags, "failure", latency_ms)
        return JSONResponse({"error": "invalid totp"}, status_code=401)


@app.get("/get_base_totp")
async def get_base_totp(request: Request):
    data = await request.json() or {}
    username = data.get("username")
    user = sql_manager.get_user_by_username(username)
    return JSONResponse({"base_totp": user["totp_secret"]})


@app.get("/admin/get_captcha_token")
async def get_captcha_token(request: Request):
    global current_captcha
    group_seed = await request.json().get("group_seed", "")
    if group_seed != config['GROUP_SEED']:
        return JSONResponse({"error": "unauthorized"}, status_code=403)
    token = secrets.token_urlsafe(16)
    current_captcha = token
    return JSONResponse({"captcha_token": token}, status_code=200)

@app.post("/set_hashmode")
async def set_hashmode():
    pass

def main():
    logger.info(f"Running, defense_config={str(defense_config)}, {hash_mode=}")
    uvicorn.run(app, host="0.0.0.0", port=5000)


if __name__ == "__main__":
    main()
