#!/usr/bin/env python3
from __future__ import annotations

import argparse
import time
from typing import Any, Dict, Optional
from src.server import Server

import pyotp

# defenses = ['none', 'totp', 'captcha', 'rate_limit', 'account_lock']


class LoginClient:
    def __init__(self, server: Server, group_seed: str, timeout_s: float = 10.0):
        self.group_seed = group_seed
        self.timeout_s = timeout_s
        self.server = server


    def _fetch_captcha_token(self) -> str:
        # Server: /admin/get_captcha_token requires group_seed query param to match config['GROUP_SEED'].
        data, status_code = self.server.get_captcha_token(self.group_seed)
        if status_code != 200:
            raise RuntimeError(f"Failed to fetch captcha token: {status_code} {data}")
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
        # First call: /login
        data, status_code = self.server.login(username, password, group_seed=self.group_seed)

        # Handle rate limit (HTTP 429).
        if status_code == 429:
            # Server doesn't include Retry-After; safest is to back off.
            print("Got 429 rate limit. Backing off 60s then stopping (safe mode).")
            time.sleep(60)
            return False

        # Handle account lock (HTTP 403 with "account locked")
        if status_code == 403:
            if data.get("captcha_required") is True:
                # Fetch a valid captcha token and retry ONCE.
                captcha_token = self._fetch_captcha_token()
                data, status_code = self.server.login(username, password, 
                                                      captcha_token=captcha_token, group_seed=self.group_seed)
            else:
                print(f"Login blocked (403): {data}")
                return False

        if status_code == 301:
            # check TOTP is enabled on server, /login returns 200 with message "move to /login_totp".
            if "login_totp" in str(data.get("status", "")):

                # Try one random TOTP - it should fail
                token = pyotp.TOTP(pyotp.random_base32()).now()
                data, status_code = self.server.login_totp(username, token, group_seed=self.group_seed) 

                if status_code == 200:
                    print("TOTP step success.")
                    return True
                else:
                    print(f"TOTP step failed: {status_code} {data}")
                    return False
        
        # Otherwise, 200 on /login is full success.
        if status_code == 200:
            print("Login success.")
            return True
        
        # Something else wrong
        else:
            # print(f"Login failed: {resp.status_code} {resp.text}")
            return False
        


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
