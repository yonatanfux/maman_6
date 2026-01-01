from crack.client import LoginClient
import secrets
import string
from argparse import ArgumentParser
from src.server import Server

group_seed = 413134

def parse_args():
    parser = ArgumentParser()
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

    return args.defense, args.hash_mode


def generate_medium_password():
    letters = ''.join(secrets.choice(string.ascii_lowercase) for _ in range(3))
    digits = ''.join(secrets.choice(string.digits) for _ in range(2))
    return letters + digits


def generate_strong_password(min_len=2, max_len=16):
    length = secrets.randbelow(max_len - min_len + 1) + min_len
    return ''.join(secrets.choice(string.ascii_lowercase) for _ in range(length))


weak_passwords = []
with open('crack/popular_passwords.txt', 'r') as f:
    for line in f:
        weak_passwords.append(line.strip())


def build_password_map(med_amount = 600000, strong_amount=1500000):
    passwords = []
    with open('crack/popular_passwords.txt', 'r') as f:
        for line in f:
            passwords.append(line.strip())
    for _ in range(med_amount):
        passwords.append(generate_medium_password())
    for _ in range(strong_amount):
        passwords.append(generate_strong_password())

    return passwords


def iterate_over_user(username, passwords, server):
    counter = 0
    client = LoginClient(server, group_seed)

    for password in passwords:
        if client.attempt_login_once(username, password):
            print(f"{username}, {password}, Broke after {counter} iterations")
            return True
        else:
            #print(f"{username}, {password}, Fail!")
            counter = counter + 1
    return False


def main():
    defense, hash_mode = parse_args()
    server = Server(defense, hash_mode)

    print("Creating password map...")
    passwords = build_password_map()
    print("Password map created")

    levels = ['weak', 'medium', 'strong']
    for i in range(3):
        for idx in range(1, 10+1):
            username = f'user_{levels[i]}_{idx}'

            print(f"iterating over {username}...")
            iterate_over_user(username, passwords, server)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Exiting....")
        exit()