import sqlite3

def add_qr_table():
    try:
        conn = sqlite3.connect('instance/library.db')
        cursor = conn.cursor()
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS qr_login_request (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token VARCHAR(100) NOT NULL UNIQUE,
            status VARCHAR(20) DEFAULT 'pending',
            user_id INTEGER,
            created_at DATETIME,
            expires_at DATETIME NOT NULL
        )
        ''')
        
        conn.commit()
        print("QR table created successfully")
        conn.close()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    add_qr_table()
