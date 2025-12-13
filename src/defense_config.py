import json


class DefenseConfig:
    def __init__(self, data):
        self.totp = "totp" in data
        self.captcha = "captcha" in data
        self.rate_limit = "rate-limit" in data
        self.account_lock = "account_lock" in data

        self.no_defense = False
        self.totp = False
        self.captcha = False
        self.rate_limit = False
        self.account_lock = False

    def to_protection_flags(self):
        if self.no_defense:
            return "no_defense"
        if self.totp:
            return "totp"
        if self.captcha:
            return "captcha"
        if self.rate_limit:
            return "rate_limit"
        if self.account_lock:
            return "account_lock"

    def __str__(self):
        return json.dumps({
            "no_defense": self.no_defense,
            "totp": self.totp,
            "captcha": self.captcha,
            "rate_limit": self.rate_limit,
            "account_lock": self.account_lock
        })