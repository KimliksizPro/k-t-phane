import sqlite3
import os
from werkzeug.security import generate_password_hash

# Define paths
base_dir = os.path.dirname(os.path.abspath(__file__))
db_paths = [
    os.path.join(base_dir, 'library.db'),
    os.path.join(base_dir, 'instance', 'library.db')
]

create_user_table_sql = """
CREATE TABLE IF NOT EXISTS user (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(80) UNIQUE NOT NULL,
    password_hash VARCHAR(120)
);
"""

for db_path in db_paths:
    print(f"\nChecking database: {db_path}")
    
    # Ensure directory exists for instance/library.db
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # 1. Create User table if not exists
        cursor.execute(create_user_table_sql)
        print("- 'user' table checked/created.")
        
        # 2. Check for password_hash column (in case table existed but was old)
        cursor.execute("PRAGMA table_info(user)")
        columns = [info[1] for info in cursor.fetchall()]
        if 'password_hash' not in columns:
            print("- Adding missing 'password_hash' column...")
            cursor.execute("ALTER TABLE user ADD COLUMN password_hash VARCHAR(120)")
            conn.commit()
        
        # 3. Ensure admin user exists
        cursor.execute("SELECT * FROM user WHERE username = 'admin'")
        admin = cursor.fetchone()
        if not admin:
            print("- Creating default admin user...")
            p_hash = generate_password_hash('admin123')
            cursor.execute("INSERT INTO user (username, password_hash) VALUES (?, ?)", ('admin', p_hash))
            conn.commit()
        else:
            print("- Admin user already exists.")
            # Optional: Reset password if it's null
            if admin[2] is None: # assuming password_hash is 3rd column (index 2)
                 print("- Fixing null password for admin...")
                 p_hash = generate_password_hash('admin123')
                 cursor.execute("UPDATE user SET password_hash = ? WHERE username = 'admin'", (p_hash,))
                 conn.commit()

        conn.close()
        print("Done.")
        
    except Exception as e:
        print(f"Error processing {db_path}: {e}")
