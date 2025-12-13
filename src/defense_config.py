import json


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