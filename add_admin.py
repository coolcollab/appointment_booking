import sqlite3
import bcrypt
import os

def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password

# Database setup
db_name = "rootdb.db"
db_exists = os.path.exists(db_name)
conn = sqlite3.connect(db_name)
c = conn.cursor()

if not db_exists:
    c.execute('''
        CREATE TABLE IF NOT EXISTS admin (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password BLOB,
            role TEXT DEFAULT 'manager'
        )
    ''')
    conn.commit()

c.execute("SELECT COUNT(*) FROM admin")
if c.fetchone()[0] == 0:
    root_username = "YOUR_USERNAME"
    root_password = "YOUR_PASSWORD"
    root_role = "root"
    root_hashed_password = hash_password(root_password)

    c.execute("INSERT INTO admin (username, password, role) VALUES (?, ?, ?)",
              (root_username, root_hashed_password, root_role))
    conn.commit()

conn.close()
