import string
import secrets

def generate_medium_password():
    letters = ''.join(secrets.choice(string.ascii_lowercase) for _ in range(5))
    digits = ''.join(secrets.choice(string.digits) for _ in range(2))
    return letters + digits

print(generate_medium_password())