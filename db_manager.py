import sqlite3
import os
from base64 import urlsafe_b64encode, urlsafe_b64decode

class DatabaseManager:
    def __init__(self, db_name="vault.db"):
        self.db_path = os.path.join(os.path.dirname(__file__), db_name)
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        self._create_tables()

    def _create_tables(self):
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service_name TEXT NOT NULL,
                username TEXT NOT NULL,
                encrypted_password BLOB NOT NULL,
                iv BLOB NOT NULL,
                tag BLOB NOT NULL,
                notes TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )""")

        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS vault_config (
                key TEXT PRIMARY KEY,
                value BLOB
            )""")

        self.conn.commit()

    def save_credential(self, service, username, encrypted_password, iv, tag, notes=""):
        try:
            self.cursor.execute(
                "INSERT INTO credentials (service_name, username, encrypted_password, iv, tag, notes) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (service, username,
                 urlsafe_b64encode(encrypted_password),
                 urlsafe_b64encode(iv),
                 urlsafe_b64encode(tag),
                 notes)
            )
            self.conn.commit()
            return True
        except Exception:
            return False

    def get_credentials(self):
        self.cursor.execute("SELECT id, service_name, username, encrypted_password, iv, tag, notes FROM credentials")
        return self.cursor.fetchall()

    def update_credential(self, cred_id, service, username, encrypted_password, iv, tag, notes):
        try:
            self.cursor.execute("""
                UPDATE credentials SET 
                service_name=?, username=?, encrypted_password=?, iv=?, tag=?, notes=?, 
                updated_at=CURRENT_TIMESTAMP WHERE id=?""",
                (service, username,
                 urlsafe_b64encode(encrypted_password),
                 urlsafe_b64encode(iv),
                 urlsafe_b64encode(tag),
                 notes, cred_id)
            )
            self.conn.commit()
            return True
        except Exception:
            return False

    def delete_credential(self, cred_id):
        try:
            self.cursor.execute("DELETE FROM credentials WHERE id=?", (cred_id,))
            self.conn.commit()
            return True
        except Exception:
            return False

    def save_config(self, key: str, value: bytes):
        try:
            self.cursor.execute("INSERT OR REPLACE INTO vault_config (key, value) VALUES (?, ?)", (key, value))
            self.conn.commit()
            return True
        except Exception:
            return False

    def get_config(self, key: str):
        self.cursor.execute("SELECT value FROM vault_config WHERE key = ?", (key,))
        result = self.cursor.fetchone()
        return result[0] if result else None

    def close(self):
        self.conn.close()
