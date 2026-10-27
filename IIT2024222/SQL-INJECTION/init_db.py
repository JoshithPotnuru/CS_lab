"""
Initializes the SQLite database used by the login demo app.
Run this once before starting app.py: `python3 init_db.py`
"""
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")

def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        )
    """)

    # Seed data. In a real system these passwords would be hashed;
    # kept as plaintext here only to keep the demo focused on the
    # SQL injection variant we are studying (CWE-89 / auth bypass).
    users = [
        ("admin", "Sup3rSecretAdminPass!", "admin"),
        ("alice", "alicepw123", "user"),
        ("bob", "bobpassword", "user"),
        ("shiva", "Shiva@2026", "student"),  # demo user for the video
    ]
    cur.executemany(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        users,
    )

    conn.commit()
    conn.close()
    print(f"Database initialized at {DB_PATH}")
    print("Seed users: admin / alice / bob / shiva (see this file for passwords)")

if __name__ == "__main__":
    init_db()
