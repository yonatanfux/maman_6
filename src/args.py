import argparse
from src.defense_config import DefenseConfig


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
    hash_mode = args.hash_mode

    if "no-defense" in args.defense:
        defense_cfg.no_defense = True
        return defense_cfg, hash_mode

    defense_cfg.totp = "totp" in args.defense
    defense_cfg.captcha = "captcha" in args.defense
    defense_cfg.rate_limit = "rate-limit" in args.defense
    defense_cfg.account_lock = "account_lock" in args.defense

    return defense_cfg, hash_mode
