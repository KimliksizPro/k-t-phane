import sqlite3
import os

db_path = 'library.db'

if not os.path.exists(db_path):
    print(f"Error: Database file not found at {db_path}")
    exit(1)

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

try:
    print("Attempting to add 'role' column...")
    cursor.execute("ALTER TABLE user ADD COLUMN role VARCHAR(20) DEFAULT 'admin'")
    conn.commit()
    print("Success: Column 'role' added.")
except sqlite3.OperationalError as e:
    if "duplicate column name" in str(e):
        print("Info: Column 'role' already exists.")
    else:
        print(f"Error: {e}")
finally:
    conn.close()
