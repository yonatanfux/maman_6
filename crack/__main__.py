import time
import secrets
import string

from tqdm import tqdm
from argparse import ArgumentParser
from crack.client import LoginClient
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


def generate_strong_password(min_len=6, max_len=16):
    length = secrets.randbelow(max_len - min_len + 1) + min_len
    return "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(length))



weak_passwords = []
with open('crack/popular_passwords.txt', 'r') as f:
    for line in f:
        weak_passwords.append(line.strip())


def build_password_map(med_amount = 500000, strong_amount=1500000):
    passwords = []
    with open('crack/popular_passwords.txt', 'r') as f:
        for line in f:
            passwords.append(line.strip())
    for _ in range(med_amount):
        passwords.append(generate_medium_password())
    for _ in range(strong_amount):
        passwords.append(generate_strong_password())

    return passwords


def iterate_over_user(username, passwords, client: LoginClient, timeout=45):
    counter = 0
    start_time = time.monotonic()

    pbar = tqdm(passwords, desc=f"Trying passwords for {username}", unit="attempt", dynamic_ncols=True)
    for password in pbar:
        # Check timeout
        if time.monotonic() - start_time >= timeout:
            pbar.close()
            tqdm.write(f"[counter: {counter}] [T] Timeout: reached ({timeout} seconds) - stopping attempts")
            return False

        resp, status = client.attempt_login_once(username, password)
        if resp:
            pbar.close()
            tqdm.write(f"[counter: {counter}] [V] Success: {username} -> {password}")
            return True
        elif not resp and status == 'totp_failed':
            pbar.close()
            tqdm.write(f"[counter: {counter}] [X] TOTP fail: password correct but TOTP code failed")
            return False
        else:
            counter += 1

    pbar.close()
    tqdm.write(f"[counter: {counter}] [X] Fail: max passwords reached")
    return False



def main():
    defense, hash_mode = parse_args()
    server = Server(defense, hash_mode)
    client = LoginClient(server, group_seed)

    print("Loading password map...")
    # passwords = build_password_map()
    # with open('password_map.txt', 'w+') as f:
    #    for p in passwords:
    #        f.write(f"{p}\n")
    passwords = []
    with open('password_map.txt', 'r') as f:
        passwords = [line.strip() for line in f]
    print("Password map loaded")

    usernames = []
    levels = ['weak', 'medium', 'strong']
    for i in range(3):
        for idx in range(1, 10+1):
            usernames.append(f'user_{levels[i]}_{idx}')
    
    for username in usernames:
            print(f"iterating over {username}...")
            iterate_over_user(username, passwords, client, timeout=45)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Exiting....")
        raise SystemExit(0)
