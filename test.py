import string
import pyotp
import json

with open('users.json', 'r') as f:
    data = json.load(f)

for user in data['users']:
    user['totp_secret'] = pyotp.random_base32()

with open('users_new.json', 'w', encoding='utf-8') as f:
    json.dump(data, f, indent=4)
print(data)