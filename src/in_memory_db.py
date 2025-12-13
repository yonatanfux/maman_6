from datetime import datetime
from typing import Dict, Optional


class SqlManager:
    def __init__(self, PATH_DUMMY):
        # username -> user record
        self._users: Dict[str, dict] = {}
        self._id_counter = 1

    def insert_user(
        self,
        username: str,
        password_hash: str,
        salt: str = None,
        totp_secret: str = None,
        failed_attempts: int = 0,
        locked_until=None,
    ):
        if username in self._users:
            raise ValueError(f"User '{username}' already exists")

        user = {
            "id": self._id_counter,
            "username": username,
            "password_hash": password_hash,
            "salt": salt,
            "totp_secret": totp_secret,
            "failed_attempts": failed_attempts,
            "locked_until": locked_until,
            "created_at": datetime.utcnow(),
        }

        self._users[username] = user
        self._id_counter += 1

    def update_user_by_username(self, username: str, **fields) -> bool:
        user = self._users.get(username)
        if not user or not fields:
            return False

        for key, value in fields.items():
            if key not in user:
                raise KeyError(f"Invalid field '{key}'")
            user[key] = value

        return True

    def get_user_by_username(self, username: str) -> Optional[dict]:
        user = self._users.get(username)
        if user is None:
            return None

        # return a copy to prevent accidental mutation
        return dict(user)

    def delete_user(self, username: str) -> bool:
        return self._users.pop(username, None) is not None

    def reset(self):
        """Equivalent to DELETE FROM users"""
        self._users.clear()
        self._id_counter = 1
