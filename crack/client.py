#!/usr/bin/env python3
from __future__ import annotations

import argparse
import time
from typing import Any, Dict, Optional

import requests
import pyotp

# defenses = ['none', 'totp', 'captcha', 'rate_limit', 'account_lock']

class LoginClient:
    def __init__(self, base_url: str, group_seed: str, timeout_s: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.group_seed = group_seed
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
            if data.get("captcha_required") is True:
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
        if isinstance(data, dict) and "login_totp" in str(data.get("status", "")):

            # Try one random TOTP - it should fail
            token = pyotp.TOTP(pyotp.random_base32()).now()

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
    ap.add_argument("--username", required=True)
    ap.add_argument("--password", required=True)
    args = ap.parse_args()

    group_seed = 413134
    base_url = 'http://192.168.1.103:5000'

    client = LoginClient(base_url, group_seed)

    ok = client.attempt_login_once(args.username, args.password)
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
