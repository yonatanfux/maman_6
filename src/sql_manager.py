import sqlite3

DB_PATH = "auth.db"


class SqlManager:
    def __init__(self, DB_PATH):
        self._DB_PATH = DB_PATH
        with sqlite3.connect(self._DB_PATH) as conn:
            c = self._db.cursor()

            c.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT,
                totp_secret TEXT,
                failed_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP DEFAULT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """)


    def insert_user(self, username: str, password_hash: str, salt: str = None, 
                    totp_secret: str = None, failed_attempts: int = 0, locked_until=None):
    
        with sqlite3.connect(self._DB_PATH) as conn:
            cursor = self._db.cursor()

            cursor.execute(
                """
                INSERT INTO users (
                    username,
                    password_hash,
                    salt,
                    totp_secret,
                    failed_attempts,
                    locked_until
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    username,
                    password_hash,
                    salt,
                    totp_secret,
                    failed_attempts,
                    locked_until
                )
            )


    def update_user_by_username(self, username: str, **fields):
        if not fields:
            return False

        with sqlite3.connect(self._DB_PATH) as conn:
            cursor = conn.cursor()

            columns = ", ".join(f"{key} = ?" for key in fields.keys())
            values = list(fields.values())
            values.append(username)

            cursor.execute(
                f"""
                UPDATE users
                SET {columns}
                WHERE username = ?
                """,
                values
            )

            updated = cursor.rowcount > 0
            return updated


def get_user_by_username(self, username: str) -> dict | None:
    with sqlite3.connect(self._DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT *
            FROM users
            WHERE username = ?
            LIMIT 1
            """,
            (username,)
        )

        row = cursor.fetchone()

        if row is None:
            return None

        return dict(row)

