import sqlite3

DB_PATH = "auth.db"


class SqlManager:
    def __init__(self):
        self._db = None

    def connect(self):
        self._init_db()

    def _init_db(self):
        self._db = sqlite3.connect(DB_PATH)
        c = self._db.cursor()
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            hash_mode TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT,
            totp_secret TEXT,
            failed_attempts INTEGER DEFAULT 0,
            locked_until TIMESTAMP DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)
        self._db.commit()
        self._db.close()

    def get_db(self):
        if self._db is None:
            self._db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
            self._db.row_factory = sqlite3.Row
        return self._db

    def close(self):
        if self._db is not None:
            self._db.close()
