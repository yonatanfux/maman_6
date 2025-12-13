#!/usr/bin/env python3
"""
Safe login-flow client for the provided Flask server.

- Uses a known credential (e.g., from your users.json) for a single target user.
- Handles: NO DEFENSE, TOTP, CAPTCHA, RATE LIMIT, ACCOUNT LOCK.
- Does NOT implement password guessing / brute force loops.

Usage:
  python client_safe.py --base-url http://127.0.0.1:5000 \
    --username alice --password 'correct-password' \
    --group-seed YOUR_GROUP_SEED \
    --defense-config defense.json

defense.json example:
{
  "totp": true,
  "captcha": true,
  "rate_limit": true,
  "account_lock": true
}
"""

# python crack/client.py --base-url http://192.168.1.103:5000 --username aaa --password bbb --group-seed 123

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests
import pyotp


@dataclass
class DefenseConfig:
    totp: bool = False
    captcha: bool = False
    rate_limit: bool = False
    account_lock: bool = False

    @staticmethod
    def from_file(path: Optional[str]) -> "DefenseConfig":
        if not path:
            return DefenseConfig()
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f) or {}
        return DefenseConfig(
            totp=bool(data.get("totp", False)),
            captcha=bool(data.get("captcha", False)),
            rate_limit=bool(data.get("rate_limit", False)),
            account_lock=bool(data.get("account_lock", False)),
        )


class LoginClient:
    def __init__(self, base_url: str, group_seed: str, defenses: DefenseConfig, timeout_s: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.group_seed = group_seed
        self.defenses = defenses
        self.timeout_s = timeout_s
        self.session = requests.Session()

    def _post_json(self, path: str, payload: Dict[str, Any]) -> requests.Response:
        url = f"{self.base_url}{path}"
        return self.session.post(url, json=payload, timeout=self.timeout_s)

    def _get_json(self, path: str, params: Optional[Dict[str, Any]] = None, json_body: Optional[Dict[str, Any]] = None) -> requests.Response:
        # Note: your server reads JSON body in GET handlers too (nonstandard but present).
        url = f"{self.base_url}{path}"
        return self.session.get(url, params=params, json=json_body, timeout=self.timeout_s)

    def _fetch_captcha_token(self) -> str:
        # Server: /admin/get_captcha_token requires group_seed query param to match config['GROUP_SEED'].
        resp = self._get_json("/admin/get_captcha_token", params={"group_seed": self.group_seed})
        if resp.status_code != 200:
            raise RuntimeError(f"Failed to fetch captcha token: {resp.status_code} {resp.text}")
        data = resp.json()
        token = data.get("captcha_token")
        if not token:
            raise RuntimeError(f"No captcha_token in response: {data}")
        return str(token)

    def _fetch_totp_secret(self, username: str) -> str:
        # Server: /get_base_totp returns {"base_totp": user["totp_secret"]}.
        resp = self._get_json("/get_base_totp", json_body={"username": username})
        if resp.status_code != 200:
            raise RuntimeError(f"Failed to fetch base TOTP secret: {resp.status_code} {resp.text}")
        data = resp.json()
        secret = data.get("base_totp")
        if not secret:
            raise RuntimeError(f"No base_totp in response: {data}")
        return str(secret)

    def attempt_login_once(self, username: str, password: str) -> bool:
        """
        Performs a single end-to-end login attempt:
        - /login with username/password (+captcha token if required)
        - if TOTP enabled and server returns partial, then /login_totp

        Returns True if fully authenticated, else False.
        """
        payload: Dict[str, Any] = {
            "username": username,
            "password": password,
            "group_seed": self.group_seed,
        }

        captcha_token: Optional[str] = None

        # First call: /login
        resp = self._post_json("/login", payload)

        # Handle rate limit (HTTP 429).
        if resp.status_code == 429:
            # Server doesn't include Retry-After; safest is to back off.
            print("Got 429 rate limit. Backing off 60s then stopping (safe mode).")
            time.sleep(60)
            return False

        # Handle account lock (HTTP 403 with "account locked")
        if resp.status_code == 403:
            try:
                data = resp.json()
            except Exception:
                data = {}
            if data.get("captcha_required") is True and self.defenses.captcha:
                # Fetch a valid captcha token and retry ONCE.
                captcha_token = self._fetch_captcha_token()
                payload["captcha_token"] = captcha_token
                resp = self._post_json("/login", payload)
            else:
                print(f"Login blocked (403): {resp.text}")
                return False

        if resp.status_code != 200:
            print(f"Login failed: {resp.status_code} {resp.text}")
            return False

        # If TOTP is enabled on server, /login returns 200 with message "move to /login_totp".
        if self.defenses.totp:
            # We detect the server message rather than assume.
            data = {}
            try:
                data = resp.json()
            except Exception:
                pass

            if isinstance(data, dict) and "login_totp" in str(data.get("status", "")):
                secret = self._fetch_totp_secret(username)
                totp = pyotp.TOTP(secret)
                token = totp.now()

                resp2 = self._post_json("/login_totp", {
                    "username": username,
                    "totp_token": token,
                    "group_seed": self.group_seed,
                })

                if resp2.status_code == 200:
                    print("TOTP step success.")
                    return True
                else:
                    print(f"TOTP step failed: {resp2.status_code} {resp2.text}")
                    return False

        # Otherwise, 200 on /login is full success.
        print("Login success.")
        return True


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", required=True, help="e.g. http://127.0.0.1:5000")
    ap.add_argument("--username", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--group-seed", required=True, help="Must match server config['GROUP_SEED'] for captcha admin endpoint.")
    ap.add_argument("--defense-config", default=None, help="Path to JSON with {totp,captcha,rate_limit,account_lock} booleans.")
    args = ap.parse_args()

    defenses = DefenseConfig.from_file(args.defense_config)
    client = LoginClient(args.base_url, args.group_seed, defenses)

    ok = client.attempt_login_once(args.username, args.password)
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
