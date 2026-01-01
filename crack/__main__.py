from crack.client import LoginClient
import secrets
import string
from src.server import Server

group_seed = 413134

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


def build_password_map(med_amount = 300000, strong_amount=100000):
    passwords = []
    with open('crack/popular_passwords.txt', 'r') as f:
        for line in f:
            passwords.append(line.strip())
    for i in range(med_amount):
        passwords.append(generate_medium_password())
    for i in range(strong_amount):
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


passwords = build_password_map()
server = Server('totp', 'SHA_PLAIN')

for i in range(1, 30+1, 1):
    level = int(i / 10)
    if level == 0:
        state = 'weak'
    elif level == 1:
        state = 'medium'
    elif level == 2:
        state = 'strong'
    
    idx = i % 10 if i % 10 != 0 else 10
    username = f'user_{state}_{idx}'

    
    print(f"iterating over {username}...")
    iterate_over_user(username, passwords, server)

