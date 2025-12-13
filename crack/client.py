#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import time
from typing import Any, Dict, Optional

import aiohttp
import pyotp


class Resp:
    """
    A simple wrapper to mimic the interface of the original synchronous
    response object, holding pre-awaited data.
    """

    def __init__(self, status_code: int, text: str, data: Dict[str, Any]):
        self.status_code = status_code
        self.text = text
        self.data = data


class LoginClient:
    def __init__(self, session: aiohttp.ClientSession, base_url: str, group_seed: str, timeout_s: float = 10.0):
        self.base_url = base_url.rstrip("/")
        # Ensure group_seed is a string as originally typed,
        # though JSON serialization handles ints fine.
        self.group_seed = str(group_seed)
        self.timeout_s = timeout_s
        self.session = session

    async def _make_resp(self, r: aiohttp.ClientResponse) -> Resp:
        """Helper to await response body and return a clean Resp object."""
        text = await r.text()
        try:
            data = await r.json()
        except Exception:
            data = {}
        return Resp(r.status, text, data)

    async def _post_json(self, path: str, payload: Dict[str, Any]) -> Resp:
        url = f"{self.base_url}{path}"
        # allow_redirects=False is crucial here because the logic checks for 301 manually
        async with self.session.post(url, json=payload, timeout=self.timeout_s, allow_redirects=False) as r:
            return await self._make_resp(r)

    async def _get_json(self, path: str, params: Optional[Dict[str, Any]] = None,
                        json_body: Optional[Dict[str, Any]] = None) -> Resp:
        url = f"{self.base_url}{path}"
        async with self.session.get(url, params=params, json=json_body, timeout=self.timeout_s,
                                    allow_redirects=False) as r:
            return await self._make_resp(r)

    async def _fetch_captcha_token(self) -> str:
        # Server: /admin/get_captcha_token requires group_seed query param
        resp = await self._get_json("/admin/get_captcha_token", params={"group_seed": self.group_seed})

        if resp.status_code != 200:
            raise RuntimeError(f"Failed to fetch captcha token: {resp.status_code} {resp.text}")

        token = resp.data.get("captcha_token")
        if not token:
            raise RuntimeError(f"No captcha_token in response: {resp.data}")
        return str(token)

    async def attempt_login_once(self, username: str, password: str) -> bool:
        """
        Performs a single end-to-end login attempt asynchronously.
        """
        payload: Dict[str, Any] = {
            "username": username,
            "password": password,
            "group_seed": self.group_seed,
        }

        captcha_token: Optional[str] = None

        # First call: /login
        resp = await self._post_json("/login", payload)

        # Handle rate limit (HTTP 429).
        if resp.status_code == 429:
            print("Got 429 rate limit. Backing off 60s then stopping (safe mode).")
            # Async sleep allows other concurrent tasks to run while this waits
            await asyncio.sleep(60)
            return False

        # Handle account lock (HTTP 403 with "account locked")
        if resp.status_code == 403:
            if resp.data.get("captcha_required") is True:
                # Fetch a valid captcha token and retry ONCE.
                captcha_token = await self._fetch_captcha_token()
                payload["captcha_token"] = captcha_token
                resp = await self._post_json("/login", payload)
            else:
                print(f"Login blocked (403): {resp.text}")
                return False

        # Handle TOTP Redirect logic (HTTP 301)
        if resp.status_code == 301:
            # check TOTP is enabled on server, /login returns message "move to /login_totp".
            if "login_totp" in str(resp.data.get("status", "")):

                # Try one random TOTP - it should fail
                token = pyotp.TOTP(pyotp.random_base32()).now()

                resp2 = await self._post_json("/login_totp", {
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
        if resp.status_code == 200:
            print("Login success.")
            return True

        # Something else wrong
        else:
            # print(f"Login failed: {resp.status_code} {resp.text}")
            return False


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--username", required=True)
    ap.add_argument("--password", required=True)
    args = ap.parse_args()

    group_seed = 413134
    base_url = 'http://192.168.1.103:5000'

    # Create the session once and pass it to the client
    async with aiohttp.ClientSession() as session:
        client = LoginClient(session, base_url, str(group_seed))

        # In a real concurrent scenario, you would create multiple tasks here
        # e.g., await asyncio.gather(client.attempt_login_once(...), ...)
        ok = await client.attempt_login_once(args.username, args.password)

    return 0 if ok else 2


if __name__ == "__main__":
    try:
        sys_exit_code = asyncio.run(main())
        raise SystemExit(sys_exit_code)
    except KeyboardInterrupt:
        pass