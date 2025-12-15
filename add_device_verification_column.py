import sqlite3
import os

db_path = 'library.db'

def migrate():
    if not os.path.exists(db_path):
        print("Database not found.")
        return

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        # Check if column exists
        cursor.execute("PRAGMA table_info(user)")
        columns = [info[1] for info in cursor.fetchall()]
        
        if 'device_verification_enabled' not in columns:
            print("Adding 'device_verification_enabled' column to 'user' table...")
            cursor.execute("ALTER TABLE user ADD COLUMN device_verification_enabled BOOLEAN DEFAULT 1")
            conn.commit()
            print("Migration successful: Column added.")
        else:
            print("Column 'device_verification_enabled' already exists.")
            
    except Exception as e:
        print(f"Error during migration: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    migrate()
