import sqlite3
import os

# Check both possible locations
databases = ['library.db', 'instance/library.db']

for db_path in databases:
    if not os.path.exists(db_path):
        continue
        
    print(f"\n--- Checking database at {db_path} ---")
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # List all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        # 1. Fix Settings table (theme)
        if 'settings' in tables:
            cursor.execute("PRAGMA table_info(settings)")
            columns = [info[1] for info in cursor.fetchall()]
            if 'theme' not in columns:
                print("Adding 'theme' column to 'settings' table...")
                cursor.execute("ALTER TABLE settings ADD COLUMN theme VARCHAR(20) DEFAULT 'blue'")
                conn.commit()
                print("Added 'theme' column.")
        
        # 2. Fix User table (password_hash)
        if 'user' in tables:
            cursor.execute("PRAGMA table_info(user)")
            columns = [info[1] for info in cursor.fetchall()]
            if 'password_hash' not in columns:
                print("Adding 'password_hash' column to 'user' table...")
                cursor.execute("ALTER TABLE user ADD COLUMN password_hash VARCHAR(120)")
                conn.commit()
                print("Added 'password_hash' column.")
            else:
                print("'password_hash' column already exists.")
        
        conn.close()
    except Exception as e:
        print(f"Error processing {db_path}: {e}")

print("\nDatabase update check completed.")
