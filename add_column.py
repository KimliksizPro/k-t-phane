import sqlite3
import os

databases = ['library.db', 'instance/library.db']

for db_path in databases:
    if not os.path.exists(db_path):
        continue
        
    print(f"\n--- Checking database at {db_path} ---")
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if column exists
        cursor.execute("PRAGMA table_info(settings)")
        columns = [info[1] for info in cursor.fetchall()]
        
        if 'active_watcher_id' not in columns:
            print("Adding 'active_watcher_id' column to 'settings' table...")
            cursor.execute("ALTER TABLE settings ADD COLUMN active_watcher_id INTEGER")
            conn.commit()
            print("Added 'active_watcher_id' column.")
        else:
            print("'active_watcher_id' column already exists.")
            
        conn.close()
    except Exception as e:
        print(f"Error processing {db_path}: {e}")

print("\nDatabase update completed.")
